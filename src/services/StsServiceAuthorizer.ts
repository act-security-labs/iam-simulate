import { type RequestAnalysis, type ResourceAnalysis } from '../evaluate.js'
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
   * Authorizes an STS request, accounting for STS actions that cannot be called anonymously.
   *
   * @param request the service authorization request containing the principal and policy analyses.
   * @returns the final STS authorization analysis.
   */
  public override authorize(request: ServiceAuthorizationRequest): RequestAnalysis {
    const action = request.request.action.value()
    const principal = request.request.principal

    if (
      action.localeCompare('sts:getcalleridentity', undefined, { sensitivity: 'accent' }) === 0 &&
      principal.isAuthenticated()
    ) {
      return {
        result: 'Allowed',
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
