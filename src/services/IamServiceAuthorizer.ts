import { type RequestAnalysis } from '../evaluate.js'
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
      resourceParts.resource?.toLowerCase()?.startsWith('role/aws-reserved/')
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
