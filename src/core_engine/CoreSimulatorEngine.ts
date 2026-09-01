import { type Policy, type Statement } from '@actsecurity/iam-policy'
import { requestMatchesStatementActions } from '../action/action.js'
import { type ConditionMatchResult, requestMatchesConditions } from '../condition/condition.js'
import { allowStatementExpression, always, and, never, or } from '../analysis/allowedConditions.js'
import { DiscoveryContextKeyConstraints } from '../context_keys/discoveryContextKeyConstraints.js'
import {
  type EvaluationResult,
  type IdentityAnalysis,
  type IgnoredCondition,
  type IgnoredConditions,
  type OuScpAnalysis,
  type RcpAnalysis,
  type RequestAnalysis,
  type ResourceAnalysis,
  type ScpAnalysis
} from '../evaluate.js'
import { type ExplainPrincipalMatch, type StatementExplain } from '../explain/statementExplain.js'
import {
  type PrincipalMatchResult,
  requestMatchesStatementPrincipals
} from '../principal/principal.js'
import { type PolicyType } from '../policyType.js'
import { type AwsRequest } from '../request/request.js'
import { requestMatchesStatementResources } from '../resource/resource.js'
import { DefaultServiceAuthorizer } from '../services/DefaultServiceAuthorizer.js'
import { IamServiceAuthorizer } from '../services/IamServiceAuthorizer.js'
import { KmsServiceAuthorizer } from '../services/KmsServiceAuthorizer.js'
import { type ServiceAuthorizer, type ServiceSettings } from '../services/ServiceAuthorizer.js'
import { S3ServiceAuthorizer } from '../services/s3/S3ServiceAuthorizer.js'
import { StsServiceAuthorizer } from '../services/StsServiceAuthorizer.js'
import {
  identityStatementAllows,
  identityStatementExplicitDeny,
  reportIgnoredConditions,
  type StatementAnalysis,
  statementMatches
} from '../StatementAnalysis.js'

export const validSimulationModes = ['Strict', 'Discovery'] as const

export type PolicyWithName = Policy<{ name: string }>

/**
 * The mode of simulation for the core engine.
 * - Strict: Simulates the request as if it were being made in a real AWS environment.
 * - Discovery: Simulates the request but discovers under what conditions it would be allowed.
 */
export type SimulationMode = (typeof validSimulationModes)[number]

/**
 * Meta parameters for the simulation engine.
 */
export interface SimulationParameters {
  /**
   * The simulation mode to use for the request.
   */
  simulationMode: SimulationMode

  /**
   * Discovery-only knowledge constraints for context keys. In Strict mode,
   * all condition keys are evaluated against the concrete request context.
   */
  discoveryContextKeyConstraints: DiscoveryContextKeyConstraints
}

/**
 * A set of service or resource control policies for each level of an organization tree
 */
export interface ControlPolicies {
  /**
   * The organization identifier for the organizational unit these policies apply to.
   */
  orgIdentifier: string

  /**
   * The policies that apply to this organizational unit.
   */
  policies: PolicyWithName[]
}

/**
 * A request to authorize a service action.
 */
export interface AuthorizationRequest {
  /**
   * The request to authorize.
   */
  request: AwsRequest

  /**
   * A session policy, if any, for the current Role or Federated User session.
   */
  sessionPolicy: PolicyWithName | undefined

  /**
   * The identity policies that are applicable to the principal making the request.
   */
  identityPolicies: PolicyWithName[]

  /**
   * The service control policies that apply to the principal making the request. In
   * order of the organization hierarchy. So the root ou SCPs should be first.
   */
  serviceControlPolicies: ControlPolicies[]

  /**
   * The resource control policies that apply to the resource being accessed. In
   * order of the organization hierarchy. So the root ou RCPs should be first.
   */
  resourceControlPolicies: ControlPolicies[]

  /**
   * The resource policy that applies to the resource being accessed.
   */
  resourcePolicy: PolicyWithName | undefined

  /**
   * The permission boundaries that apply to the principal making the request.
   */
  permissionBoundaries: PolicyWithName[] | undefined

  /**
   * The VPC endpoint policies that apply to the request, if any.
   */
  vpcEndpointPolicies: PolicyWithName[] | undefined

  /**
   * The simulation parameters for the request.
   */
  simulationParameters: SimulationParameters

  /**
   * Caller-supplied service-specific settings that affect authorization.
   */
  serviceSettings?: ServiceSettings
}

const serviceEngines: Record<string, new () => ServiceAuthorizer> = {
  kms: KmsServiceAuthorizer,
  sts: StsServiceAuthorizer,
  iam: IamServiceAuthorizer,
  s3: S3ServiceAuthorizer
}

/**
 * Authorizes a request.
 *
 * This assumes all policies have been validated and the request is fully complete and valid.
 *
 * @param request the request to authorize
 * @returns the result of the authorization
 */
export function authorize(request: AuthorizationRequest): RequestAnalysis {
  const principalHasPermissionBoundary =
    !!request.permissionBoundaries && request.permissionBoundaries.length > 0
  const simulationParameters = request.simulationParameters

  const sessionAnalysis = request.sessionPolicy
    ? analyzeIdentityPolicies(
        [request.sessionPolicy],
        request.request,
        simulationParameters,
        'session'
      )
    : undefined

  const identityAnalysis = analyzeIdentityPolicies(
    request.identityPolicies,
    request.request,
    simulationParameters,
    'identity'
  )

  const permissionBoundaryAnalysis = analyzePermissionBoundaryPolicies(
    request.permissionBoundaries,
    request.request,
    simulationParameters
  )

  const scpAnalysis = analyzeControlPolicies(
    request.serviceControlPolicies,
    request.request,
    simulationParameters,
    'scp'
  ) as ScpAnalysis

  const rcpAnalysis = analyzeControlPolicies(
    request.resourceControlPolicies,
    request.request,
    simulationParameters,
    'rcp'
  ) as RcpAnalysis

  const resourceAnalysis = analyzeResourcePolicy(
    request.resourcePolicy,
    request.request,
    principalHasPermissionBoundary,
    simulationParameters
  )

  const endpointAnalysis = analyzeVpcEndpointPolicies(
    request.vpcEndpointPolicies,
    request.request,
    simulationParameters
  )

  const serviceAuthorizer = getServiceAuthorizer(request)
  const result = serviceAuthorizer.authorize({
    request: request.request,
    sessionAnalysis,
    identityAnalysis,
    scpAnalysis,
    rcpAnalysis,
    resourceAnalysis,
    resourcePolicy: request.resourcePolicy,
    permissionBoundaryAnalysis,
    endpointAnalysis,
    simulationParameters,
    serviceSettings: request.serviceSettings
  })

  if (simulationParameters.simulationMode === 'Discovery') {
    result.ignoredConditions = ignoredConditionsAnalysis(
      sessionAnalysis,
      scpAnalysis,
      rcpAnalysis,
      identityAnalysis,
      resourceAnalysis,
      permissionBoundaryAnalysis,
      endpointAnalysis
    )
    result.ignoredRoleSessionName = roleSessionNameIgnored(
      sessionAnalysis,
      scpAnalysis,
      rcpAnalysis,
      identityAnalysis,
      resourceAnalysis,
      permissionBoundaryAnalysis
    )
  }

  return result
}

/**
 * Get the appropriate service authorizer for the request. Some services have specific authorization logic in
 * them. If there is no service specific authorizer, a default one will be used.
 *
 * @param request the request to get the authorizer for
 * @returns the service authorizer for the request
 */
export function getServiceAuthorizer(request: AuthorizationRequest): ServiceAuthorizer {
  const serviceName = request.request.action.service().toLowerCase()
  if (serviceEngines[serviceName]) {
    return new serviceEngines[serviceName]()
  }
  return new DefaultServiceAuthorizer()
}

/**
 * Analyzes a set of identity policies
 *
 * @param identityPolicies the identity policies to analyze
 * @param request the request to analyze against
 * @returns an array of statement analysis results
 */
export function analyzeIdentityPolicies(
  identityPolicies: PolicyWithName[],
  request: AwsRequest,
  simulationParameters: SimulationParameters,
  policyType: PolicyType
): IdentityAnalysis {
  const identityAnalysis: IdentityAnalysis = {
    result: 'ImplicitlyDenied',
    allowStatements: [],
    denyStatements: [],
    unmatchedStatements: []
  }

  for (const policy of identityPolicies) {
    for (const statement of policy.statements()) {
      const { matches: resourceMatch, details: resourceDetails } = requestMatchesStatementResources(
        request,
        statement,
        policyType
      )
      const { matches: actionMatch, details: actionDetails } = requestMatchesStatementActions(
        request,
        statement
      )
      const {
        matches: conditionMatch,
        details: conditionDetails,
        ignoredConditions
      } = requestMatchesConditions(
        request,
        statement.conditions(),
        statement.effect() as 'Allow' | 'Deny',
        simulationParameters
      )

      const principalMatch: PrincipalMatchResult = 'Match'
      const overallMatch = statementMatches({
        actionMatch,
        conditionMatch,
        principalMatch,
        resourceMatch
      })

      const shouldReportIgnoredConditions = reportIgnoredConditions({
        actionMatch,
        principalMatch,
        resourceMatch
      })

      const statementAnalysis: StatementAnalysis = {
        policyId: policy.metadata().name,
        statement,
        resourceMatch,
        actionMatch,
        conditionMatch,
        principalMatch,
        ignoredConditions: shouldReportIgnoredConditions ? ignoredConditions : undefined,
        explain: makeStatementExplain(
          statement,
          overallMatch,
          actionMatch,
          principalMatch,
          resourceMatch,
          conditionMatch,
          { ...resourceDetails, ...actionDetails, ...conditionDetails }
        )
      }

      if (identityStatementExplicitDeny(statementAnalysis)) {
        identityAnalysis.denyStatements.push(statementAnalysis)
      } else if (identityStatementAllows(statementAnalysis)) {
        identityAnalysis.allowStatements.push(statementAnalysis)
      } else {
        identityAnalysis.unmatchedStatements.push(statementAnalysis)
      }
    }
  }

  if (identityAnalysis.denyStatements.length > 0) {
    identityAnalysis.result = 'ExplicitlyDenied'
  } else if (identityAnalysis.allowStatements.length > 0) {
    identityAnalysis.result = 'Allowed'
  }

  return identityAnalysis
}

/**
 * Analyzes a set of service or resource control policies and the statements within them.
 *
 * @param controlPolicies the control policies to analyze
 * @param request the request to analyze against
 * @returns an array of SCP or RCP analysis results
 */
export function analyzeControlPolicies(
  controlPolicies: ControlPolicies[],
  request: AwsRequest,
  simulationParameters: SimulationParameters,
  policyType: PolicyType
): ScpAnalysis | RcpAnalysis {
  const analysis: OuScpAnalysis[] = []
  for (const controlPolicy of controlPolicies) {
    const ouAnalysis: OuScpAnalysis = {
      orgIdentifier: controlPolicy.orgIdentifier,
      result: 'ImplicitlyDenied',
      allowStatements: [],
      denyStatements: [],
      unmatchedStatements: [],
      conditions: never('noApplicableAllow')
    }
    for (const policy of controlPolicy.policies) {
      for (const statement of policy.statements()) {
        const { matches: resourceMatch, details: resourceDetails } =
          requestMatchesStatementResources(request, statement, policyType)
        const { matches: actionMatch, details: actionDetails } = requestMatchesStatementActions(
          request,
          statement
        )
        const {
          matches: conditionMatch,
          details: conditionDetails,
          ignoredConditions
        } = requestMatchesConditions(
          request,
          statement.conditions(),
          statement.effect() as 'Allow' | 'Deny',
          simulationParameters
        )

        const principalMatch: PrincipalMatchResult = 'Match'
        const overallMatch = statementMatches({
          actionMatch,
          conditionMatch,
          principalMatch,
          resourceMatch
        })

        const shouldReportIgnoredConditions = reportIgnoredConditions({
          actionMatch,
          principalMatch,
          resourceMatch
        })

        const statementAnalysis: StatementAnalysis = {
          policyId: policy.metadata().name,
          statement,
          resourceMatch,
          actionMatch,
          conditionMatch,
          principalMatch,
          ignoredConditions: shouldReportIgnoredConditions ? ignoredConditions : [],
          explain: makeStatementExplain(
            statement,
            overallMatch,
            actionMatch,
            principalMatch,
            resourceMatch,
            conditionMatch,
            { ...resourceDetails, ...actionDetails, ...conditionDetails }
          )
        }

        if (identityStatementAllows(statementAnalysis)) {
          ouAnalysis.allowStatements.push(statementAnalysis)
        } else if (identityStatementExplicitDeny(statementAnalysis)) {
          ouAnalysis.denyStatements.push(statementAnalysis)
        } else {
          ouAnalysis.unmatchedStatements.push(statementAnalysis)
        }
      }
    }

    if (ouAnalysis.denyStatements.length > 0) {
      ouAnalysis.result = 'ExplicitlyDenied'
    } else if (ouAnalysis.allowStatements.length > 0) {
      ouAnalysis.result = 'Allowed'
    }

    if (ouAnalysis.result === 'Allowed') {
      ouAnalysis.conditions = or(
        ouAnalysis.allowStatements.map((statement) =>
          allowStatementExpression(
            statement,
            policyType as 'scp' | 'rcp',
            controlPolicy.orgIdentifier
          )
        )
      )
    }
    analysis.push(ouAnalysis)
  }

  let overallResult: EvaluationResult = 'ImplicitlyDenied'
  if (analysis.some((ou) => ou.result === 'ExplicitlyDenied')) {
    overallResult = 'ExplicitlyDenied'
  } else if (analysis.some((ou) => ou.allowStatements.length === 0)) {
    overallResult = 'ImplicitlyDenied'
  } else if (analysis.every((ou) => ou.result === 'Allowed')) {
    overallResult = 'Allowed'
  }

  return {
    result: overallResult,
    ouAnalysis: analysis,
    conditions:
      analysis.length === 0
        ? always()
        : overallResult === 'Allowed'
          ? and(analysis.map((ou) => ou.conditions))
          : never('noApplicableAllow')
  }
}

/**
 * Analyze a resource policy and return the results
 *
 * @param resourcePolicy the resource policy to analyze
 * @param request the request to analyze against
 * @returns an array of statement analysis results
 */
export function analyzeResourcePolicy(
  resourcePolicy: PolicyWithName | undefined,
  request: AwsRequest,
  principalHasPermissionBoundary: boolean,
  simulationParameters: SimulationParameters
): ResourceAnalysis {
  const resourceAnalysis: ResourceAnalysis = {
    result: 'NotApplicable',
    allowStatements: [],
    denyStatements: [],
    unmatchedStatements: []
  }

  if (!resourcePolicy) {
    return resourceAnalysis
  }

  const principalMatchOptions: PrincipalMatchResult[] = [
    'Match',
    'SessionRoleMatch',
    'SessionUserMatch'
  ]

  for (const statement of resourcePolicy.statements()) {
    const { matches: resourceMatch, details: resourceDetails } = requestMatchesStatementResources(
      request,
      statement,
      'resource'
    )
    const { matches: actionMatch, details: actionDetails } = requestMatchesStatementActions(
      request,
      statement
    )
    let {
      matches: principalMatch,
      details: principalDetails,
      ignoredRoleSessionName
    } = requestMatchesStatementPrincipals(request, statement, simulationParameters)

    const permissionBoundaryDetails: Pick<StatementExplain, 'denyBecauseNpInRpAndPb'> = {}

    /**
     * "Don't use resource-based policy statements that include a NotPrincipal policy element with a
     * Deny effect for IAM users or roles that have a permissions boundary policy attached.
     * The NotPrincipal element with a Deny effect will always deny any IAM principal that
     * has a permissions boundary policy attached, regardless of the values specified in the
     * NotPrincipal element. This causes some IAM users or roles that would otherwise have access
     * to the resource to lose access. We recommend changing your resource-based policy statements
     * to use the condition operator ArnNotEquals with the aws:PrincipalArn context key to limit
     * access instead of the NotPrincipal element. For information about permissions boundaries, see
     * Permissions boundaries for IAM entities."
     * https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html
     */
    if (
      principalHasPermissionBoundary &&
      statement.isNotPrincipalStatement() &&
      statement.effect() === 'Deny'
    ) {
      principalMatch = 'Match'
      permissionBoundaryDetails.denyBecauseNpInRpAndPb = true
    }

    const {
      matches: conditionMatch,
      details: conditionDetails,
      ignoredConditions
    } = requestMatchesConditions(
      request,
      statement.conditions(),
      statement.effect() as 'Allow' | 'Deny',
      simulationParameters
    )

    const overallMatch = statementMatches({
      actionMatch,
      conditionMatch,
      principalMatch,
      resourceMatch
    })

    const shouldReportIgnoredConditions = reportIgnoredConditions({
      actionMatch,
      principalMatch,
      resourceMatch
    })

    const analysis: StatementAnalysis = {
      policyId: resourcePolicy.metadata().name,
      statement,
      resourceMatch: resourceMatch,
      actionMatch,
      conditionMatch,
      principalMatch,
      ignoredConditions: shouldReportIgnoredConditions ? ignoredConditions : undefined,
      ignoredRoleSessionName,
      explain: makeStatementExplain(
        statement,
        overallMatch,
        actionMatch,
        principalMatch,
        resourceMatch,
        conditionMatch,
        { ...resourceDetails, ...actionDetails, ...principalDetails, ...conditionDetails }
      )
    }
    if (identityStatementExplicitDeny(analysis) && analysis.principalMatch !== 'NoMatch') {
      resourceAnalysis.denyStatements.push(analysis)
    } else if (identityStatementAllows(analysis) && analysis.principalMatch !== 'NoMatch') {
      resourceAnalysis.allowStatements.push(analysis)
    } else {
      resourceAnalysis.unmatchedStatements.push(analysis)
    }
  }

  if (
    resourceAnalysis.denyStatements.some((s) => principalMatchOptions.includes(s.principalMatch))
  ) {
    resourceAnalysis.result = 'ExplicitlyDenied'
  } else if (
    resourceAnalysis.denyStatements.some((s) => s.principalMatch === 'AccountLevelMatch')
  ) {
    resourceAnalysis.result = 'DeniedForAccount'
  } else if (
    resourceAnalysis.allowStatements.some((s) => principalMatchOptions.includes(s.principalMatch))
  ) {
    resourceAnalysis.result = 'Allowed'
  } else if (
    resourceAnalysis.allowStatements.some((s) => s.principalMatch === 'AccountLevelMatch')
  ) {
    resourceAnalysis.result = 'AllowedForAccount'
  } else {
    resourceAnalysis.result = 'ImplicitlyDenied'
  }

  return resourceAnalysis
}

export function analyzePermissionBoundaryPolicies(
  permissionBoundaries: PolicyWithName[] | undefined,
  request: AwsRequest,
  simulationParameters: SimulationParameters
): IdentityAnalysis | undefined {
  if (!permissionBoundaries || permissionBoundaries.length === 0) {
    return undefined
  }

  return analyzeIdentityPolicies(permissionBoundaries, request, simulationParameters, 'pb')
}

export function analyzeVpcEndpointPolicies(
  vpcEndPointPolicies: PolicyWithName[] | undefined,
  request: AwsRequest,
  simulationParameters: SimulationParameters
): IdentityAnalysis | undefined {
  if (!vpcEndPointPolicies || vpcEndPointPolicies.length === 0) {
    return undefined
  }
  return analyzeIdentityPolicies(vpcEndPointPolicies, request, simulationParameters, 'vpce')
}

function makeStatementExplain(
  statement: Statement,
  overallMatch: boolean,
  actionMatch: boolean,
  principalMatch: ExplainPrincipalMatch,
  resourceMatch: boolean,
  conditionMatch: ConditionMatchResult,
  details: Partial<StatementExplain>
): StatementExplain {
  return {
    effect: statement.effect(),
    identifier: statement.sid() || statement.index().toString(),
    matches: overallMatch,
    actionMatch,
    principalMatch,
    resourceMatch,
    conditionMatch: conditionMatch === 'Match',
    ...details
  }
}

/**
 * Create an analysis of the ignored conditions in all statements.
 *
 * @param scpAnalysis the SCP analysis
 * @param rcpAnalysis the RCP analysis
 * @param identityAnalysis the identity analysis
 * @param resourceAnalysis the resource analysis
 * @param permissionBoundaryAnalysis the permission boundary analysis (optional)
 * @returns an object containing the ignored conditions for each analysis
 */
function ignoredConditionsAnalysis(
  sessionAnalysis: IdentityAnalysis | undefined,
  scpAnalysis: ScpAnalysis,
  rcpAnalysis: RcpAnalysis,
  identityAnalysis: IdentityAnalysis,
  resourceAnalysis: ResourceAnalysis,
  permissionBoundaryAnalysis?: IdentityAnalysis,
  endpointAnalysis?: IdentityAnalysis
): IgnoredConditions | undefined {
  const ignoredConditions: IgnoredConditions = {}
  if (sessionAnalysis) {
    addIgnoredConditionsToAnalysis(ignoredConditions, 'session', [sessionAnalysis])
  }
  addIgnoredConditionsToAnalysis(ignoredConditions, 'scp', scpAnalysis.ouAnalysis)
  addIgnoredConditionsToAnalysis(ignoredConditions, 'rcp', rcpAnalysis.ouAnalysis)
  addIgnoredConditionsToAnalysis(ignoredConditions, 'identity', [identityAnalysis])
  addIgnoredConditionsToAnalysis(ignoredConditions, 'resource', [resourceAnalysis])
  addIgnoredConditionsToAnalysis(
    ignoredConditions,
    'permissionBoundary',
    permissionBoundaryAnalysis ? [permissionBoundaryAnalysis] : []
  )
  addIgnoredConditionsToAnalysis(
    ignoredConditions,
    'endpointPolicy',
    endpointAnalysis ? [endpointAnalysis] : []
  )

  if (Object.keys(ignoredConditions).length > 0) {
    return ignoredConditions
  }
  return undefined
}

/**
 * Adds the specified ignored conditions to the analysis.
 *
 * @param analyses the analyses to map ignored conditions from
 * @returns the ignored conditions for allow and deny statements
 */
function addIgnoredConditionsToAnalysis(
  ignoredConditions: Partial<IgnoredConditions>,
  key: keyof IgnoredConditions,
  analyses: {
    denyStatements: StatementAnalysis[]
    allowStatements: StatementAnalysis[]
    unmatchedStatements: StatementAnalysis[]
  }[]
): void {
  const allow: IgnoredCondition[] = []
  const deny: IgnoredCondition[] = []
  const allStatements = analyses.flatMap((analysis) => [
    ...analysis.allowStatements,
    ...analysis.denyStatements,
    ...analysis.unmatchedStatements
  ])

  for (const statement of allStatements) {
    if (statement.ignoredConditions && statement.ignoredConditions.length > 0) {
      if (statement.statement.isAllow()) {
        allow.push(
          ...statement.ignoredConditions.map((c) => ({
            op: c.operation().value(),
            key: c.conditionKey(),
            values: c.conditionValues()
          }))
        )
      } else {
        deny.push(
          ...statement.ignoredConditions.map((c) => ({
            op: c.operation().value(),
            key: c.conditionKey(),
            values: c.conditionValues()
          }))
        )
      }
    }
  }

  if (allow.length === 0 && deny.length === 0) {
    return
  }
  const newValue: IgnoredConditions[keyof IgnoredConditions] = {}
  if (allow.length > 0) {
    newValue.allow = allow
  }
  if (deny.length > 0) {
    newValue.deny = deny
  }
  ignoredConditions[key] = newValue as IgnoredConditions[keyof IgnoredConditions]
}

/**
 * Checks all analyses to see if any of them have statements that ignore the role session name.
 *
 * @param scpAnalysis the SCP analysis
 * @param rcpAnalysis the RCP analysis
 * @param identityAnalysis the identity analysis
 * @param resourceAnalysis the resource analysis
 * @param permissionBoundaryAnalysis the permission boundary analysis (optional)
 * @returns true if any analysis has statements that ignore the role session name, false otherwise
 */
function roleSessionNameIgnored(
  sessionAnalysis: IdentityAnalysis | undefined,
  scpAnalysis: ScpAnalysis,
  rcpAnalysis: RcpAnalysis,
  identityAnalysis: IdentityAnalysis,
  resourceAnalysis: ResourceAnalysis,
  permissionBoundaryAnalysis?: IdentityAnalysis
): boolean {
  return (
    sessionAnalysis?.allowStatements.some((s) => s.ignoredRoleSessionName) ||
    sessionAnalysis?.unmatchedStatements.some((s) => s.ignoredRoleSessionName) ||
    scpAnalysis.ouAnalysis.some((ou) => ou.allowStatements.some((s) => s.ignoredRoleSessionName)) ||
    scpAnalysis.ouAnalysis.some((ou) =>
      ou.unmatchedStatements.some((s) => s.ignoredRoleSessionName)
    ) ||
    rcpAnalysis.ouAnalysis.some((ou) => ou.allowStatements.some((s) => s.ignoredRoleSessionName)) ||
    rcpAnalysis.ouAnalysis.some((ou) =>
      ou.unmatchedStatements.some((s) => s.ignoredRoleSessionName)
    ) ||
    identityAnalysis.allowStatements.some((s) => s.ignoredRoleSessionName) ||
    identityAnalysis.unmatchedStatements.some((s) => s.ignoredRoleSessionName) ||
    resourceAnalysis.allowStatements.some((s) => s.ignoredRoleSessionName) ||
    resourceAnalysis.unmatchedStatements.some((s) => s.ignoredRoleSessionName) ||
    permissionBoundaryAnalysis?.allowStatements.some((s) => s.ignoredRoleSessionName) ||
    permissionBoundaryAnalysis?.unmatchedStatements.some((s) => s.ignoredRoleSessionName) ||
    false
  )
}
