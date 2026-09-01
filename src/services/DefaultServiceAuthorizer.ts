import {
  allDenyEscapeExpressions,
  allowedConditionOutput,
  and,
  endpointPolicyExpression,
  identityPolicyExpression,
  or,
  permissionBoundaryExpression,
  resourceAllowStatementsExpression,
  sessionPolicyExpression
} from '../analysis/allowedConditions.js'
import {
  isAssumedRoleArn,
  isFederatedUserArn,
  isIamRoleArn,
  isIamUserArn,
  isServicePrincipal
} from '@actsecurity/iam-utils'
import {
  type AllowedConditionExpression,
  type BlockedReason,
  type EvaluationResult,
  type RequestAnalysis,
  type ResourceAnalysis
} from '../evaluate.js'
import { assertAuthenticatedRequestPrincipal } from '../request/requestPrincipal.js'
import { type RequestResource } from '../request/requestResource.js'
import { type StatementAnalysis } from '../StatementAnalysis.js'
import { type ServiceAuthorizationRequest, type ServiceAuthorizer } from './ServiceAuthorizer.js'

/**
 * This helper class keeps track of which factors are blocking a request and what the overall result is
 * based on those blocks.
 */
class BlockedByLog {
  private blockedBy: Set<BlockedReason> = new Set()
  private result: EvaluationResult

  /**
   * Create the BlockedByLog
   *
   * @param coreResult the core result of the authorization. Is the request allowed or denied based on the core policies (identity, resource, session).
   */
  constructor(private readonly coreResult: EvaluationResult) {
    this.result = coreResult
  }

  /**
   * Add a blocking factor to the log and update the overall result accordingly.
   *
   * @param reason the reason for the block.
   * @param result the result of the block (ImplicitlyDenied, ExplicitlyDenied)
   */
  add(reason: BlockedReason, result: EvaluationResult) {
    if (this.coreResult === 'Allowed' && result !== 'Allowed') {
      this.blockedBy.add(reason)
    }

    this.setResult(result)
  }

  /**
   * Calculates and sets the new overall result based on the new block reason and the previous result.
   *
   * The result can only be modified down so Allowed -> ImplicitlyDenied -> ExplicitlyDenied.
   *
   * @param newResult the result of the new block reason being added.
   */
  private setResult(newResult: EvaluationResult) {
    // Explicit denies override everything
    if (this.result === 'ExplicitlyDenied') {
      return
    }
    if (newResult === 'ExplicitlyDenied') {
      this.result = 'ExplicitlyDenied'
    } else if (newResult === 'ImplicitlyDenied') {
      this.result = 'ImplicitlyDenied'
    }
  }

  /**
   * Get the overall result after all blocks (if any) have been added.
   *
   * @returns the overall result after all blocks (if any) have been added.
   */
  getResult(): EvaluationResult {
    return this.result
  }

  /**
   * Get the list of reasons that are blocking the request after the core result.
   *
   * @returns an array of reasons that are blocking the request after the core result.
   */
  getBlockedBy(): BlockedReason[] {
    return Array.from(this.blockedBy)
  }
}

interface InitialEvaluation {
  result: EvaluationResult
  conditions: AllowedConditionExpression
}

interface PermissionBoundaryMutation {
  result?: EvaluationResult
  conditions: AllowedConditionExpression
}

export type PrincipalAccountTrust =
  | { trustType: 'Implicit' }
  | { trustType: 'Explicit'; statements: StatementAnalysis[] }
  | { trustType: 'None' }

/**
 * The default authorizer for services.
 */
export class DefaultServiceAuthorizer implements ServiceAuthorizer {
  /**
   * Authorize a service request after all policy analysis has been completed.
   *
   * @param request the service authorization request containing all analyses
   * @returns the result of the authorization
   */
  public authorize(request: ServiceAuthorizationRequest): RequestAnalysis {
    const scpResult = request.scpAnalysis.result
    const rcpResult = request.rcpAnalysis.result
    const identityStatementResult = request.identityAnalysis.result
    const resourcePolicyResult = request.resourceAnalysis?.result
    const endpointPolicyResult = request.endpointAnalysis?.result

    const requestPrincipal = request.request.principal
    const principalAccount = requestPrincipal.isAuthenticated()
      ? requestPrincipal.accountId()
      : undefined
    const resourceAccount = request.request.resource?.accountId()
    const sameAccount = principalAccount !== undefined && principalAccount === resourceAccount

    const baseResult: Pick<
      RequestAnalysis,
      | 'sameAccount'
      | 'scpAnalysis'
      | 'rcpAnalysis'
      | 'resourceAnalysis'
      | 'sessionAnalysis'
      | 'identityAnalysis'
      | 'permissionBoundaryAnalysis'
      | 'endpointAnalysis'
      | 'blockedBy'
    > = {
      sameAccount,
      sessionAnalysis: request.sessionAnalysis,
      identityAnalysis: request.identityAnalysis,
      scpAnalysis: request.scpAnalysis,
      rcpAnalysis: request.rcpAnalysis,
      resourceAnalysis: request.resourceAnalysis,
      permissionBoundaryAnalysis: request.permissionBoundaryAnalysis,
      endpointAnalysis: request.endpointAnalysis
    }

    if (requestPrincipal.isAnonymous()) {
      return this.authorizeAnonymousRequest(request, baseResult)
    }
    assertAuthenticatedRequestPrincipal(requestPrincipal)

    const initialEvaluation = this.initialEvaluationResult(request)
    let coreConditions = initialEvaluation.conditions
    const blockedByLog = new BlockedByLog(initialEvaluation.result)

    blockedByLog.add('scp', scpResult)
    blockedByLog.add('rcp', rcpResult)

    if (
      endpointPolicyResult === 'ExplicitlyDenied' ||
      endpointPolicyResult === 'ImplicitlyDenied'
    ) {
      blockedByLog.add('vpce', endpointPolicyResult)
    }

    if (
      resourcePolicyResult === 'ExplicitlyDenied' ||
      resourcePolicyResult === 'DeniedForAccount'
    ) {
      blockedByLog.add('resource', 'ExplicitlyDenied')
    }

    if (identityStatementResult === 'ExplicitlyDenied') {
      blockedByLog.add('identity', 'ExplicitlyDenied')
    }

    const permissionBoundaryMutation = this.applyPermissionBoundaryToCoreConditions(
      request,
      sameAccount,
      coreConditions
    )
    coreConditions = permissionBoundaryMutation.conditions
    if (permissionBoundaryMutation.result) {
      blockedByLog.add('pb', permissionBoundaryMutation.result)
    }

    const blockedReasons = blockedByLog.getBlockedBy()
    if (blockedReasons.length !== 0) {
      baseResult.blockedBy = blockedReasons
    }

    const finalResult = blockedByLog.getResult()
    return {
      result: finalResult,
      ...baseResult,
      conditions: this.conditionsForAllowedResult(request, coreConditions, finalResult)
    }

    /**
     * Add checks for:
     * * root user - can override resource policies for most resource types
     * * organization APIs and delegated admin policy
     */
  }

  /**
   * Authorize an anonymous request after all policy analysis has been completed.
   *
   * @param request the service authorization request containing all analyses.
   * @param baseResult the common request-analysis fields to include in the result.
   * @returns the anonymous request authorization result.
   */
  private authorizeAnonymousRequest(
    request: ServiceAuthorizationRequest,
    baseResult: Pick<
      RequestAnalysis,
      | 'sameAccount'
      | 'scpAnalysis'
      | 'rcpAnalysis'
      | 'resourceAnalysis'
      | 'sessionAnalysis'
      | 'identityAnalysis'
      | 'permissionBoundaryAnalysis'
      | 'endpointAnalysis'
      | 'blockedBy'
    >
  ): RequestAnalysis {
    const endpointPolicyResult = request.endpointAnalysis?.result
    const initialEvaluation = this.anonymousInitialEvaluationResult(request)
    const blockedByLog = new BlockedByLog(initialEvaluation.result)

    if (request.rcpAnalysis.ouAnalysis.length > 0) {
      blockedByLog.add('rcp', request.rcpAnalysis.result)
    }

    if (
      endpointPolicyResult === 'ExplicitlyDenied' ||
      endpointPolicyResult === 'ImplicitlyDenied'
    ) {
      blockedByLog.add('vpce', endpointPolicyResult)
    }

    const blockedReasons = blockedByLog.getBlockedBy()
    if (blockedReasons.length !== 0) {
      baseResult.blockedBy = blockedReasons
    }

    const finalResult = blockedByLog.getResult()
    return {
      result: finalResult,
      ...baseResult,
      sameAccount: false,
      conditions: this.conditionsForAllowedResult(
        request,
        initialEvaluation.conditions,
        finalResult
      )
    }
  }

  /**
   * Evaluates whether an anonymous request has the resource-side grant required to be allowed.
   *
   * @param request the service authorization request containing all analyses.
   * @returns the core anonymous result before applicable resource-side guardrails are applied.
   */
  private anonymousInitialEvaluationResult(
    request: ServiceAuthorizationRequest
  ): InitialEvaluation {
    const resourcePolicyResult = request.resourceAnalysis?.result
    if (resourcePolicyResult === 'Allowed') {
      return {
        result: 'Allowed',
        conditions: resourceAllowStatementsExpression(request.resourceAnalysis.allowStatements)
      }
    }
    if (
      resourcePolicyResult === 'ExplicitlyDenied' ||
      resourcePolicyResult === 'DeniedForAccount'
    ) {
      return {
        result: 'ExplicitlyDenied',
        conditions: { conditionType: 'never', reason: 'noApplicableAllow' }
      }
    }
    return {
      result: 'ImplicitlyDenied',
      conditions: { conditionType: 'never', reason: 'noApplicableAllow' }
    }
  }

  /**
   * Determines if the service trusts the principal's Account's IAM policies
   *
   * @param sameAccount - If the principal and resource are in the same account
   * @param resourceAnalysis - The resource policy analysis
   * @returns true if the service trusts the principal's account IAM policies
   */
  serviceTrustsPrincipalAccount(
    sameAccount: boolean,
    resourceAnalysis: ResourceAnalysis,
    resource: RequestResource
  ): PrincipalAccountTrust {
    if (sameAccount) {
      return { trustType: 'Implicit' }
    }

    const accountLevelStatements = this.accountLevelResourceAllowStatements(resourceAnalysis)
    if (accountLevelStatements.length > 0) {
      return { trustType: 'Explicit', statements: accountLevelStatements }
    }

    return { trustType: 'None' }
  }

  /**
   * Combine core authorization conditions with guardrail conditions for a final allowed result.
   *
   * @param request the service authorization request containing all analyses
   * @param coreConditions the conditions for the core service authorization decision after permission-boundary mutation
   * @param finalResult the final authorization result after guardrails
   * @returns the public conditions expression, or undefined when none should be emitted
   */
  protected conditionsForAllowedResult(
    request: ServiceAuthorizationRequest,
    coreConditions: AllowedConditionExpression,
    finalResult: EvaluationResult
  ): AllowedConditionExpression | undefined {
    const expressions = [
      sessionPolicyExpression(request.sessionAnalysis, request.sessionAnalysis !== undefined),
      coreConditions,
      request.scpAnalysis.conditions,
      request.rcpAnalysis.conditions
    ]

    if (request.endpointAnalysis?.result === 'Allowed') {
      expressions.push(endpointPolicyExpression(request.endpointAnalysis))
    }

    expressions.push(
      ...allDenyEscapeExpressions({
        sessionAnalysis: request.sessionAnalysis,
        scpAnalysis: request.scpAnalysis,
        rcpAnalysis: request.rcpAnalysis,
        identityAnalysis: request.identityAnalysis,
        resourceAnalysis: request.resourceAnalysis,
        permissionBoundaryAnalysis: request.permissionBoundaryAnalysis,
        endpointAnalysis: request.endpointAnalysis
      })
    )

    return allowedConditionOutput(
      and(expressions),
      request.simulationParameters.simulationMode,
      finalResult
    )
  }

  /**
   * Apply permission-boundary effects to the core authorization conditions.
   *
   * Permission boundaries are not part of the core service authorization result. This function lives
   * with the permission-boundary authorization checks and recalculates the affected condition paths
   * only when permission-boundary behavior changes which core path can be used.
   *
   * @param request the service authorization request containing all analyses
   * @param sameAccount whether the principal and resource are in the same account
   * @param coreConditions the unmodified core authorization conditions
   * @returns the permission-boundary block result, if any, and updated core conditions
   */
  private applyPermissionBoundaryToCoreConditions(
    request: ServiceAuthorizationRequest,
    sameAccount: boolean,
    coreConditions: AllowedConditionExpression
  ): PermissionBoundaryMutation {
    const permissionBoundaryResult = request.permissionBoundaryAnalysis?.result
    if (!permissionBoundaryResult) {
      return { conditions: coreConditions }
    }

    if (permissionBoundaryResult === 'ExplicitlyDenied') {
      return { result: 'ExplicitlyDenied', conditions: coreConditions }
    }

    if (permissionBoundaryResult === 'Allowed') {
      return {
        conditions: this.coreConditionsWithAllowedPermissionBoundary(request, sameAccount)
      }
    }

    if (permissionBoundaryResult === 'ImplicitlyDenied') {
      if (!sameAccount) {
        return { result: 'ImplicitlyDenied', conditions: coreConditions }
      }

      const bypassStatements = this.permissionBoundaryBypassResourceAllowStatements(request)
      if (bypassStatements.length === 0) {
        return { result: 'ImplicitlyDenied', conditions: coreConditions }
      }

      return { conditions: resourceAllowStatementsExpression(bypassStatements) }
    }

    return { conditions: coreConditions }
  }

  /**
   * Recalculate core conditions when an allowed permission boundary constrains identity-policy paths.
   *
   * @param request the service authorization request containing all analyses
   * @param sameAccount whether the principal and resource are in the same account
   * @returns core conditions with permission-boundary allow conditions applied to identity paths
   */
  private coreConditionsWithAllowedPermissionBoundary(
    request: ServiceAuthorizationRequest,
    sameAccount: boolean
  ): AllowedConditionExpression {
    const principal = request.request.principal
    if (principal.isAnonymous()) {
      return resourceAllowStatementsExpression(request.resourceAnalysis.allowStatements)
    }
    assertAuthenticatedRequestPrincipal(principal)

    if (isServicePrincipal(principal.value())) {
      return resourceAllowStatementsExpression(request.resourceAnalysis.allowStatements)
    }

    if (sameAccount) {
      const trustedAccount = this.serviceTrustsPrincipalAccount(
        sameAccount,
        request.resourceAnalysis,
        request.request.resource
      )
      return this.sameAccountConditionsWithAllowedPermissionBoundary(request, trustedAccount)
    }

    if (
      (request.resourceAnalysis.result === 'Allowed' ||
        request.resourceAnalysis.result === 'AllowedForAccount') &&
      request.identityAnalysis.result === 'Allowed'
    ) {
      return and([
        this.crossAccountResourcePolicyConditions(request),
        identityPolicyExpression(request.identityAnalysis),
        permissionBoundaryExpression(request.permissionBoundaryAnalysis)
      ])
    }

    return { conditionType: 'never', reason: 'noApplicableAllow' }
  }

  /**
   * Recalculate same-account conditions when an allowed permission boundary constrains identity paths.
   *
   * @param request the service authorization request containing all analyses
   * @param trustedAccount how the service trusts the principal account for this request
   * @returns same-account core conditions with permission-boundary allow conditions applied to identity paths
   */
  private sameAccountConditionsWithAllowedPermissionBoundary(
    request: ServiceAuthorizationRequest,
    trustedAccount: PrincipalAccountTrust
  ): AllowedConditionExpression {
    switch (trustedAccount.trustType) {
      case 'Implicit':
        return this.sameAccountImplicitTrustConditionsWithAllowedPermissionBoundary(request)
      case 'Explicit':
        return this.sameAccountExplicitTrustConditionsWithAllowedPermissionBoundary(
          request,
          trustedAccount
        )
      case 'None':
        return request.resourceAnalysis.result === 'Allowed'
          ? this.sameAccountResourcePolicyConditions(request)
          : { conditionType: 'never', reason: 'noApplicableAllow' }
      default:
        throw new Error(
          `Unrecognized principal account trust type: ${String((trustedAccount as { trustType: unknown }).trustType)}`
        )
    }
  }

  /**
   * Recalculate same-account implicit trust conditions when permission-boundary allow constrains identity paths.
   *
   * @param request the service authorization request containing all analyses
   * @returns same-account implicit trust conditions with permission-boundary allow conditions applied to identity paths
   */
  private sameAccountImplicitTrustConditionsWithAllowedPermissionBoundary(
    request: ServiceAuthorizationRequest
  ): AllowedConditionExpression {
    const resourceConditions =
      request.resourceAnalysis.result === 'Allowed'
        ? this.sameAccountResourcePolicyConditions(request)
        : { conditionType: 'never' as const, reason: 'noApplicableAllow' as const }
    const identityConditions =
      request.identityAnalysis.result === 'Allowed'
        ? and([
            identityPolicyExpression(request.identityAnalysis),
            permissionBoundaryExpression(request.permissionBoundaryAnalysis)
          ])
        : { conditionType: 'never' as const, reason: 'noApplicableAllow' as const }

    return or([resourceConditions, identityConditions])
  }

  /**
   * Recalculate same-account explicit trust conditions when permission-boundary allow constrains identity paths.
   *
   * @param request the service authorization request containing all analyses
   * @param trustedAccount explicit account-trust statements selected by the service authorizer
   * @returns same-account explicit trust conditions with permission-boundary allow conditions applied to identity paths
   */
  private sameAccountExplicitTrustConditionsWithAllowedPermissionBoundary(
    request: ServiceAuthorizationRequest,
    trustedAccount: Extract<PrincipalAccountTrust, { trustType: 'Explicit' }>
  ): AllowedConditionExpression {
    const resourceConditions =
      request.resourceAnalysis.result === 'Allowed'
        ? this.sameAccountResourcePolicyConditions(request)
        : { conditionType: 'never' as const, reason: 'noApplicableAllow' as const }
    const identityConditions =
      request.identityAnalysis.result === 'Allowed'
        ? and([
            resourceAllowStatementsExpression(trustedAccount.statements),
            identityPolicyExpression(request.identityAnalysis),
            permissionBoundaryExpression(request.permissionBoundaryAnalysis)
          ])
        : { conditionType: 'never' as const, reason: 'noApplicableAllow' as const }

    return or([resourceConditions, identityConditions])
  }

  /**
   * Get resource-policy allow statements that matched the principal directly.
   *
   * @param resourceAnalysis resource-policy analysis containing already-matched allow statements
   * @returns direct principal-match resource allow statements
   */
  private directResourceAllowStatements(resourceAnalysis: ResourceAnalysis): StatementAnalysis[] {
    return resourceAnalysis.allowStatements.filter((statement) =>
      ['Match', 'SessionRoleMatch', 'SessionUserMatch'].includes(statement.principalMatch)
    )
  }

  /**
   * Get resource-policy allow statements that matched at the principal-account level.
   *
   * @param resourceAnalysis resource-policy analysis containing already-matched allow statements
   * @returns account-level resource allow statements
   */
  protected accountLevelResourceAllowStatements(
    resourceAnalysis: ResourceAnalysis
  ): StatementAnalysis[] {
    return resourceAnalysis.allowStatements.filter(
      (statement) => statement.principalMatch === 'AccountLevelMatch'
    )
  }

  /**
   * Get same-account resource-policy conditions for paths that can satisfy core authorization.
   *
   * @param request the service authorization request containing all analyses
   * @returns resource-policy conditions for the allowed same-account branch
   */
  private sameAccountResourcePolicyConditions(
    request: ServiceAuthorizationRequest
  ): AllowedConditionExpression {
    return resourceAllowStatementsExpression(
      this.directResourceAllowStatements(request.resourceAnalysis)
    )
  }

  /**
   * Evaluate same-account core authorization and conditions based on principal-account trust.
   *
   * @param request the service authorization request containing all analyses
   * @param trustedAccount how the service trusts the principal account for this request
   * @returns the same-account core authorization result and conditions
   */
  private sameAccountInitialEvaluation(
    request: ServiceAuthorizationRequest,
    trustedAccount: PrincipalAccountTrust
  ): InitialEvaluation {
    switch (trustedAccount.trustType) {
      case 'Implicit':
        return this.sameAccountImplicitTrustEvaluation(request)
      case 'Explicit':
        return this.sameAccountExplicitTrustEvaluation(request, trustedAccount)
      case 'None':
        return this.sameAccountNoTrustEvaluation(request)
      default:
        throw new Error(
          `Unrecognized principal account trust type: ${String((trustedAccount as { trustType: unknown }).trustType)}`
        )
    }
  }

  /**
   * Evaluate same-account authorization when the service implicitly trusts identity policies.
   *
   * @param request the service authorization request containing all analyses
   * @returns the same-account authorization result and conditions
   */
  private sameAccountImplicitTrustEvaluation(
    request: ServiceAuthorizationRequest
  ): InitialEvaluation {
    const resourcePolicyResult = request.resourceAnalysis.result
    const identityStatementResult = request.identityAnalysis.result

    if (resourcePolicyResult === 'Allowed' && identityStatementResult === 'Allowed') {
      return {
        result: 'Allowed',
        conditions: or([
          this.sameAccountResourcePolicyConditions(request),
          identityPolicyExpression(request.identityAnalysis)
        ])
      }
    }

    if (resourcePolicyResult === 'Allowed') {
      return {
        result: 'Allowed',
        conditions: this.sameAccountResourcePolicyConditions(request)
      }
    }

    if (identityStatementResult === 'Allowed') {
      return {
        result: 'Allowed',
        conditions: identityPolicyExpression(request.identityAnalysis)
      }
    }

    return {
      result: 'ImplicitlyDenied',
      conditions: { conditionType: 'never', reason: 'noApplicableAllow' }
    }
  }

  /**
   * Evaluate same-account authorization when the service requires explicit resource-policy account trust.
   *
   * @param request the service authorization request containing all analyses
   * @param trustedAccount explicit account-trust statements selected by the service authorizer
   * @returns the same-account authorization result and conditions
   */
  private sameAccountExplicitTrustEvaluation(
    request: ServiceAuthorizationRequest,
    trustedAccount: Extract<PrincipalAccountTrust, { trustType: 'Explicit' }>
  ): InitialEvaluation {
    const resourcePolicyResult = request.resourceAnalysis.result
    const identityStatementResult = request.identityAnalysis.result
    const resourceConditions =
      resourcePolicyResult === 'Allowed'
        ? this.sameAccountResourcePolicyConditions(request)
        : { conditionType: 'never' as const, reason: 'noApplicableAllow' as const }

    if (identityStatementResult === 'Allowed') {
      const identityConditions = and([
        resourceAllowStatementsExpression(trustedAccount.statements),
        identityPolicyExpression(request.identityAnalysis)
      ])
      return {
        result: 'Allowed',
        conditions: or([resourceConditions, identityConditions])
      }
    }

    if (resourcePolicyResult === 'Allowed') {
      return {
        result: 'Allowed',
        conditions: resourceConditions
      }
    }

    return {
      result: 'ImplicitlyDenied',
      conditions: { conditionType: 'never', reason: 'noApplicableAllow' }
    }
  }

  /**
   * Evaluate same-account authorization when the service does not trust identity policies.
   *
   * @param request the service authorization request containing all analyses
   * @returns the same-account authorization result and conditions
   */
  private sameAccountNoTrustEvaluation(request: ServiceAuthorizationRequest): InitialEvaluation {
    if (request.resourceAnalysis.result === 'Allowed') {
      return {
        result: 'Allowed',
        conditions: this.sameAccountResourcePolicyConditions(request)
      }
    }

    return {
      result: 'ImplicitlyDenied',
      conditions: { conditionType: 'never', reason: 'noApplicableAllow' }
    }
  }

  /**
   * Get resource-policy conditions for a cross-account request's resource-policy side.
   *
   * @param request the service authorization request containing all analyses
   * @returns resource-policy conditions for the matching cross-account resource-policy statements
   */
  private crossAccountResourcePolicyConditions(
    request: ServiceAuthorizationRequest
  ): AllowedConditionExpression {
    if (
      request.resourceAnalysis.result !== 'Allowed' &&
      request.resourceAnalysis.result !== 'AllowedForAccount'
    ) {
      return { conditionType: 'never', reason: 'noApplicableAllow' }
    }

    return resourceAllowStatementsExpression([
      ...this.directResourceAllowStatements(request.resourceAnalysis),
      ...this.accountLevelResourceAllowStatements(request.resourceAnalysis)
    ])
  }

  /**
   * Get same-account resource-policy allow statements that bypass an implicit permission-boundary deny.
   *
   * @param request the service authorization request containing all analyses
   * @returns resource-policy allow statements that bypass the implicit permission-boundary deny
   */
  private permissionBoundaryBypassResourceAllowStatements(
    request: ServiceAuthorizationRequest
  ): StatementAnalysis[] {
    if (request.resourceAnalysis.result !== 'Allowed') {
      return []
    }

    const principal = request.request.principal
    if (!principal.isAuthenticated()) {
      return []
    }
    const principalValue = principal.value()

    if (
      isAssumedRoleArn(principalValue) ||
      isIamUserArn(principalValue) ||
      isFederatedUserArn(principalValue)
    ) {
      return request.resourceAnalysis.allowStatements.filter(
        (statement) => statement.principalMatch === 'Match'
      )
    }

    if (isIamRoleArn(principalValue)) {
      return request.resourceAnalysis.allowStatements.filter(
        (statement) =>
          statement.principalMatch === 'Match' &&
          (statement.ignoredRoleSessionName ||
            (statement.statement.isPrincipalStatement() &&
              statement.statement.principals().some((p) => p.isWildcardPrincipal())))
      )
    }

    return []
  }

  /**
   * Evaluations whether the minimum requirements for the request to be allowed are met based on the core policies
   *   - Identity
   *   - Resource
   *   - Session
   *
   * Depending on the service, and whether the principal and resources are in the same account, the requirements may differ.
   * For same account requests, for most services an Allow in the resource policy or the identity policy is sufficient to
   * allow the request, so this function will return 'Allowed'. If there is an explicit deny elsewhere, that is not considered.
   * This function only determines if there are enough core policies to allow the request, and final determination of the
   * request is done elsewhere.
   *
   * @param request the service authorization request containing all analyses
   * @returns 'Allowed' if the core policies allow the request, otherwise may return 'ImplicitlyDenied' or 'ExplicitlyDenied' depending on the analyses
   */
  private initialEvaluationResult(request: ServiceAuthorizationRequest): InitialEvaluation {
    const sessionResult = request.sessionAnalysis?.result
    const identityStatementResult = request.identityAnalysis.result
    const resourcePolicyResult = request.resourceAnalysis?.result

    const requestPrincipal = request.request.principal
    const principalAccount = requestPrincipal.isAuthenticated()
      ? requestPrincipal.accountId()
      : undefined
    const resourceAccount = request.request.resource?.accountId()
    const sameAccount = principalAccount !== undefined && principalAccount === resourceAccount
    if (requestPrincipal.isAnonymous()) {
      return this.anonymousInitialEvaluationResult(request)
    }
    assertAuthenticatedRequestPrincipal(requestPrincipal)

    if (sessionResult && sessionResult !== 'Allowed') {
      return {
        result: sessionResult,
        conditions: sessionPolicyExpression(request.sessionAnalysis, true)
      }
    }

    // Service Principals
    if (isServicePrincipal(requestPrincipal.value())) {
      // Service principals are allowed if the resource policy allows them
      if (resourcePolicyResult === 'Allowed') {
        return {
          result: 'Allowed',
          conditions: resourceAllowStatementsExpression(request.resourceAnalysis.allowStatements)
        }
      }
      return {
        result: 'ImplicitlyDenied',
        conditions: { conditionType: 'never', reason: 'noApplicableAllow' }
      }
    }

    //Same Account
    if (sameAccount) {
      const trustedAccount = this.serviceTrustsPrincipalAccount(
        sameAccount,
        request.resourceAnalysis,
        request.request.resource
      )
      return this.sameAccountInitialEvaluation(request, trustedAccount)
    }

    //Cross Account
    if (resourcePolicyResult === 'Allowed' || resourcePolicyResult === 'AllowedForAccount') {
      if (identityStatementResult === 'Allowed') {
        const coreConditions = and([
          this.crossAccountResourcePolicyConditions(request),
          identityPolicyExpression(request.identityAnalysis)
        ])
        return {
          result: 'Allowed',
          conditions: coreConditions
        }
      }
    }

    return {
      result: 'ImplicitlyDenied',
      conditions: { conditionType: 'never', reason: 'noApplicableAllow' }
    }
  }
}
