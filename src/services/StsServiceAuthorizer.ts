import { isIamUserArn } from '@actsecurity/iam-utils'
import { type EvaluationResult, type RequestAnalysis, type ResourceAnalysis } from '../evaluate.js'
import { type RequestPrincipal } from '../request/requestPrincipal.js'
import { type RequestResource } from '../request/requestResource.js'
import { DefaultServiceAuthorizer, type PrincipalAccountTrust } from './DefaultServiceAuthorizer.js'
import { type ServiceAuthorizationRequest } from './ServiceAuthorizer.js'

const actionsRequiringAuthenticatedPrincipal = new Set([
  'sts:assumerole',
  'sts:getcalleridentity',
  'sts:getsessiontoken'
])

/**
 * Service authorizer for AWS Security Token Service requests.
 */
export class StsServiceAuthorizer extends DefaultServiceAuthorizer {
  /**
   * Authorizes an STS request. A request AWS decides by its caller alone gets that result with no policy
   * analysis, so no denial reason read from it names a policy: none took part. Any other request goes through
   * policy evaluation, and STS actions that cannot be called anonymously are denied to anonymous callers.
   *
   * @param request the service authorization request containing the principal and policy analyses.
   * @returns the final STS authorization analysis.
   */
  public override authorize(request: ServiceAuthorizationRequest): RequestAnalysis {
    const action = request.request.action.value()
    const principal = request.request.principal

    const policyFreeResult = resultWithoutPolicies({ action, principal })
    if (policyFreeResult !== null) {
      return {
        result: policyFreeResult,
        sameAccount: true,
        conditions: undefined
      }
    }

    const baseResult = super.authorize(request)
    if (
      principal.isAnonymous() &&
      actionsRequiringAuthenticatedPrincipal.has(action.toLowerCase())
    ) {
      return {
        ...baseResult,
        result: 'ImplicitlyDenied',
        conditions: undefined
      }
    }

    return baseResult
  }

  /**
   * Determines if the service trusts the principal's Account's IAM policies
   *
   * @param sameAccount - If the principal and resource are in the same account
   * @param resourceAnalysis - The resource policy analysis
   * @returns how the service trusts the principal's account IAM policies
   */
  override serviceTrustsPrincipalAccount(
    sameAccount: boolean,
    resourceAnalysis: ResourceAnalysis,
    resource: RequestResource
  ): PrincipalAccountTrust {
    //If there is no resource policy, the service trusts the principal's account IAM policies
    if (sameAccount && resourceAnalysis.result === 'NotApplicable') {
      return { trustType: 'Implicit' }
    }

    /*
      If there is a resource policy, for instance a role trust policy,
      the trust policy must explicitly allow the principal's account,
      even if the principal and resource are in the same account.
    */
    const accountLevelStatements = this.accountLevelResourceAllowStatements(resourceAnalysis)
    if (accountLevelStatements.length > 0) {
      return { trustType: 'Explicit', statements: accountLevelStatements }
    }

    return { trustType: 'None' }
  }
}

/** A result AWS reaches without reading any policy. */
type PolicyFreeResult = Extract<EvaluationResult, 'Allowed' | 'ImplicitlyDenied'>

const rootArnRegex = /^arn:[a-zA-Z-]+:iam::\d{12}:root$/

/**
 * The STS actions AWS decides by their authenticated caller alone, each with its result for a caller. No identity
 * policy, session policy, permissions boundary, SCP or RCP takes part, an explicit Deny included:
 * - GetCallerIdentity: allowed for any caller.
 * - GetSessionToken: allowed for an IAM user or the root user, the only callers whose credentials AWS accepts for
 *   it. Any other caller (a role or role session, a federated user, a service) is rejected whatever its policies
 *   allow; the simulator has no rejected-credential result, so it answers ImplicitlyDenied. Known gap: a call made
 *   with the session credentials GetSessionToken returned is rejected too, but it appears as the IAM user's ARN, and
 *   the request carries no credential type, so the simulator answers Allowed.
 */
const resultForCallerByAction = new Map<string, (principalValue: string) => PolicyFreeResult>([
  ['sts:getcalleridentity', () => 'Allowed'],
  [
    'sts:getsessiontoken',
    (principalValue) =>
      isIamUserArn(principalValue) || rootArnRegex.test(principalValue)
        ? 'Allowed'
        : 'ImplicitlyDenied'
  ]
])

/**
 * The result of an STS request AWS decides by its authenticated caller alone.
 *
 * @param params.action the STS action being authorized.
 * @param params.principal the request principal.
 * @returns the result AWS gives the caller, or null when the request's policies decide it.
 */
function resultWithoutPolicies({
  action,
  principal
}: {
  action: string
  principal: RequestPrincipal
}): PolicyFreeResult | null {
  const resultForCaller = resultForCallerByAction.get(action.toLowerCase())
  if (resultForCaller === undefined || !principal.isAuthenticated()) {
    return null
  }
  return resultForCaller(principal.value())
}
