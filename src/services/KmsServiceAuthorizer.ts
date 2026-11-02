import { equalsIgnoreCase } from '@actsecurity/iam-utils'
import { type RequestAnalysis, type ResourceAnalysis } from '../evaluate.js'
import { type RequestResource } from '../request/requestResource.js'
import { DefaultServiceAuthorizer, type PrincipalAccountTrust } from './DefaultServiceAuthorizer.js'
import { type ServiceAuthorizationRequest } from './ServiceAuthorizer.js'

const deniedActionsForAwsManagedAliases = new Set([
  'kms:createalias',
  'kms:deletealias',
  'kms:updatealias'
])
const awsManagedAliasPrefix = 'alias/aws/'

/**
 * Checks whether the KMS resource should use KMS key-policy principal-account trust behavior.
 *
 * @param resource the request resource to classify
 * @returns true when the resource is all resources or a KMS key resource
 */
function usesKmsKeyPrincipalAccountTrust(resource: RequestResource): boolean {
  return resource.isAllResources() || resource.resource().toLowerCase().startsWith('key/')
}

/**
 * Checks whether the KMS resource is an AWS-managed key alias.
 *
 * @param resource the request resource to classify
 * @returns true when the resource is an alias/aws/... ARN resource
 */
function isAwsManagedAlias(resource: RequestResource): boolean {
  return equalsIgnoreCase(
    resource.resource().slice(0, awsManagedAliasPrefix.length),
    awsManagedAliasPrefix
  )
}

/**
 * Service authorizer for AWS KMS requests.
 */
export class KmsServiceAuthorizer extends DefaultServiceAuthorizer {
  /**
   * Authorize a KMS service request after policy analysis and KMS-specific managed alias checks.
   *
   * @param request the service authorization request containing all analyses
   * @returns the KMS authorization result
   */
  public override authorize(request: ServiceAuthorizationRequest): RequestAnalysis {
    const baseResult = super.authorize(request)

    if (baseResult.result === 'ExplicitlyDenied') {
      return baseResult
    }

    if (
      deniedActionsForAwsManagedAliases.has(request.request.action.value().toLowerCase()) &&
      isAwsManagedAlias(request.request.resource)
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
   * Determines how KMS trusts the principal account's IAM policies.
   *
   * KMS key resources keep KMS key-policy trust behavior, while other KMS resource types use the
   * default service authorizer trust behavior.
   *
   * @param sameAccount if the principal and resource are in the same account
   * @param resourceAnalysis the resource policy analysis
   * @param resource the request resource used to choose key or default trust behavior
   * @returns how KMS trusts the principal account's IAM policies
   */
  override serviceTrustsPrincipalAccount(
    sameAccount: boolean,
    resourceAnalysis: ResourceAnalysis,
    resource: RequestResource
  ): PrincipalAccountTrust {
    if (!usesKmsKeyPrincipalAccountTrust(resource)) {
      return super.serviceTrustsPrincipalAccount(sameAccount, resourceAnalysis, resource)
    }

    if (sameAccount && resource.isAllResources()) {
      return { trustType: 'Implicit' }
    }

    const accountLevelStatements = this.accountLevelResourceAllowStatements(resourceAnalysis)
    if (accountLevelStatements.length > 0) {
      return { trustType: 'Explicit', statements: accountLevelStatements }
    }

    return { trustType: 'None' }
  }
}
