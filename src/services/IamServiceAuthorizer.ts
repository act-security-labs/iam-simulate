import { type RequestAnalysis } from '../evaluate.js'
import { type AwsRequest } from '../request/request.js'
import { splitArnParts } from '../util.js'
import { DefaultServiceAuthorizer } from './DefaultServiceAuthorizer.js'
import { type ServiceAuthorizationRequest } from './ServiceAuthorizer.js'

const deniedActionsForManagedPolicies = new Set([
  'iam:createpolicy',
  'iam:createpolicyversion',
  'iam:deletepolicy',
  'iam:deletepolicyversion',
  'iam:setdefaultpolicyversion',
  'iam:tagpolicy',
  'iam:untagpolicy'
])

const deniedActionsForAwsManagedRoles = new Set([
  'iam:attachrolepolicy',
  'iam:createrole',
  'iam:createservicelinkedrole',
  'iam:deleterole',
  'iam:deleterolepermissionsboundary',
  'iam:deleterolepolicy',
  'iam:deleteservicelinkedrole',
  'iam:detachrolepolicy',
  'iam:passrole',
  'iam:putrolepermissionsboundary',
  'iam:putrolepolicy',
  'iam:tagrole',
  'iam:untagrole',
  'iam:updateassumerolepolicy',
  'iam:updaterole',
  'iam:updateroledescription'
])

const reservedRolePath = 'role/aws-reserved/'
const serviceLinkedRolePath = 'role/aws-service-role/'

/**
 * Gets the service named in a service-owned IAM role path, such as
 * `role/aws-reserved/sso.amazonaws.com/...`.
 *
 * @param arn the ARN to inspect
 * @param rolePath the service-owned role path the ARN must be under
 * @returns the lower-cased service segment, or undefined if the ARN is not under the path
 */
function serviceOfRolePath(arn: string, rolePath: string): string | undefined {
  const resource = splitArnParts(arn).resource?.toLowerCase()
  if (!resource?.startsWith(rolePath)) {
    return undefined
  }
  return resource.slice(rolePath.length).split('/').at(0) || undefined
}

/**
 * Checks whether the principal is the service-linked role of the service that owns the reserved
 * role. IAM lets that service manage its reserved roles, so policies decide those requests.
 *
 * @param request the request to classify
 * @returns true when the principal and resource paths name the same service
 */
function isOwningServiceLinkedRole(request: AwsRequest): boolean {
  const { principal, resource } = request
  if (!principal.isAuthenticated()) {
    return false
  }
  const owner = serviceOfRolePath(resource.value(), reservedRolePath)
  return (
    owner !== undefined && owner === serviceOfRolePath(principal.value(), serviceLinkedRolePath)
  )
}
/**
 * Service authorizer for IAM service requests.
 */
export class IamServiceAuthorizer extends DefaultServiceAuthorizer {
  public override authorize(request: ServiceAuthorizationRequest): RequestAnalysis {
    const baseResult = super.authorize(request)

    const resourceParts = splitArnParts(request.request.resource.value())
    // If the request is for a managed policy and the action is one of the denied actions,
    // we return implicitly denied.
    if (
      deniedActionsForManagedPolicies.has(request.request.action.value().toLowerCase()) &&
      resourceParts.resource?.toLowerCase()?.startsWith('policy/') &&
      resourceParts.accountId == 'aws'
    ) {
      return {
        ...baseResult,
        result: 'ImplicitlyDenied',
        // Removing policy guardrails cannot make a service-blocked request succeed.
        blockedBy: undefined,
        conditions: undefined
      }
    }

    // If the request is for an AWS managed role and the action is one of the denied actions,
    // we return implicitly denied.
    if (
      deniedActionsForAwsManagedRoles.has(request.request.action.value().toLowerCase()) &&
      resourceParts.resource?.toLowerCase()?.startsWith(reservedRolePath) &&
      !isOwningServiceLinkedRole(request.request)
    ) {
      return {
        ...baseResult,
        result: 'ImplicitlyDenied',
        // Keep policy analyses for inspection without attributing the block to them.
        blockedBy: undefined,
        conditions: undefined
      }
    }

    return baseResult
  }
}
