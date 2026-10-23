import { isIamUserArn, isRootArn } from '@actsecurity/iam-utils'
import { type EvaluationResult, type RequestAnalysis, type ResourceAnalysis } from '../evaluate.js'
import { type RequestPrincipal } from '../request/requestPrincipal.js'
import { type RequestResource } from '../request/requestResource.js'
import { DefaultServiceAuthorizer, type PrincipalAccountTrust } from './DefaultServiceAuthorizer.js'
import { type ServiceAuthorizationRequest } from './ServiceAuthorizer.js'

const actionsRequiringAuthenticatedPrincipal: readonly string[] = [
  'sts:AssumeRole',
  'sts:GetCallerIdentity',
  'sts:GetSessionToken'
]

/**
 * Service authorizer for AWS Security Token Service requests.
 */
export class StsServiceAuthorizer extends DefaultServiceAuthorizer {
  /** Authorizes an STS request, answering actions decided by the caller alone without policy evaluation. */
  public override authorize(request: ServiceAuthorizationRequest): RequestAnalysis {
    const action = request.request.action.value()
    const principal = request.request.principal

    const policyFreeResult = resultWithoutPolicies({ action, principal })
    if (policyFreeResult !== undefined) {
      return {
        result: policyFreeResult,
        sameAccount: true,
        conditions: undefined
      }
    }

    const baseResult = super.authorize(request)
    if (
      principal.isAuthenticated() &&
      isRootArn(principal.value()) &&
      isSameAction({ action, candidate: 'sts:AssumeRole' })
    ) {
      return {
        ...baseResult,
        result: 'ImplicitlyDenied',
        conditions: undefined
      }
    }

    if (
      principal.isAnonymous() &&
      actionsRequiringAuthenticatedPrincipal.some((candidate) =>
        isSameAction({ action, candidate })
      )
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

/** STS actions whose result depends only on the caller. */
const resultForCallerByAction: readonly {
  action: string
  resultForCaller: (principalValue: string) => EvaluationResult
}[] = [
  { action: 'sts:GetCallerIdentity', resultForCaller: () => 'Allowed' },
  {
    action: 'sts:GetSessionToken',
    resultForCaller: (principalValue) =>
      isIamUserArn(principalValue) || isRootArn(principalValue) ? 'Allowed' : 'ImplicitlyDenied'
  }
]

/** The result AWS gives an authenticated caller for an action decided by the caller alone, else undefined. */
function resultWithoutPolicies({
  action,
  principal
}: {
  action: string
  principal: RequestPrincipal
}): EvaluationResult | undefined {
  const entry = resultForCallerByAction.find((row) =>
    isSameAction({ action, candidate: row.action })
  )
  if (entry === undefined || !principal.isAuthenticated()) {
    return undefined
  }
  return entry.resultForCaller(principal.value())
}

function isSameAction({ action, candidate }: { action: string; candidate: string }): boolean {
  return action.localeCompare(candidate, undefined, { sensitivity: 'accent' }) === 0
}
