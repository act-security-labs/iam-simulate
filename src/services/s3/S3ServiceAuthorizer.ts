import { isCloudFrontOriginAccessUserArn, isServicePrincipal } from '@actsecurity/iam-utils'
import { resourceAllowStatementsExpression } from '../../analysis/allowedConditions.js'
import { type RequestAnalysis } from '../../evaluate.js'
import { DefaultServiceAuthorizer, type InitialEvaluation } from '../DefaultServiceAuthorizer.js'
import { type ServiceAuthorizationRequest } from '../ServiceAuthorizer.js'
import { classifyS3RuntimePublicBucketPolicy } from './s3BlockPublicAccess.js'

// Deliberate product cap: these are the S3 actions validated with live OAI requests.
const oaiAllowedActions = new Set([
  'getobject',
  'putobject',
  'deleteobject',
  'getobjectacl',
  'getobjectattributes',
  'getobjecttagging',
  'deleteobjecttagging',
  'abortmultipartupload',
  'listbucket',
  'getbucketacl',
  'getbucketlocation',
  'getbucketversioning',
  'getbucketpolicystatus',
  'getencryptionconfiguration',
  'getbucketpublicaccessblock',
  'listbucketversions',
  'listbucketmultipartuploads'
])

/**
 * Service authorizer for S3 requests that applies S3 Block Public Access runtime behavior.
 */
export class S3ServiceAuthorizer extends DefaultServiceAuthorizer {
  /**
   * Evaluate an OAI's resource-policy grant within the product's validated action cap.
   * Other principals retain the default evaluation; guardrails are applied by the parent.
   *
   * @param request the analyzed service request
   * @returns the core policy evaluation before guardrails
   */
  protected override initialEvaluationResult(
    request: ServiceAuthorizationRequest
  ): InitialEvaluation {
    const principal = request.request.principal
    if (!principal.isAuthenticated() || !isCloudFrontOriginAccessUserArn(principal.value())) {
      return super.initialEvaluationResult(request)
    }
    if (request.sessionAnalysis && request.sessionAnalysis.result !== 'Allowed') {
      return super.initialEvaluationResult(request)
    }
    if (
      oaiAllowedActions.has(request.request.action.action().toLowerCase()) &&
      request.resourceAnalysis.result === 'Allowed'
    ) {
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

  /**
   * Authorizes an S3 request and applies RestrictPublicBuckets when the caller supplied
   * S3 Block Public Access as enabled for the target bucket/account.
   *
   * @param request the service authorization request containing policy analyses and S3 settings
   * @returns the final request analysis including an S3 BPA block when applicable
   */
  public override authorize(request: ServiceAuthorizationRequest): RequestAnalysis {
    const baseResult = super.authorize(request)

    if (baseResult.result !== 'Allowed') {
      return baseResult
    }

    if (!isStandardS3BucketResource(request.request.resource.value())) {
      return baseResult
    }

    if (request.serviceSettings?.s3?.blockPublicAccess !== true) {
      return baseResult
    }

    if (!request.resourcePolicy) {
      return baseResult
    }

    const classification = classifyS3RuntimePublicBucketPolicy(request.resourcePolicy)
    if (classification.result === 'nonPublic') {
      return baseResult
    }

    if (baseResult.sameAccount) {
      return baseResult
    }

    const principal = request.request.principal
    if (principal.isAuthenticated() && isServicePrincipal(principal.value())) {
      return baseResult
    }

    // The base result is Allowed here, so there are no prior blocking reasons to merge.
    return {
      ...baseResult,
      result: 'ExplicitlyDenied',
      blockedBy: ['s3-bpa'],
      conditions: undefined
    }
  }
}

/**
 * Checks whether a resource string is a standard S3 bucket or object ARN.
 *
 * @param resource the resource string to check
 * @returns true if the resource is a standard S3 bucket/object ARN
 */
export function isStandardS3BucketResource(resource: string): boolean {
  if (resource === '*') {
    return true
  }

  const parts = resource.split(':')
  if (parts.length < 6) {
    return false
  }

  const service = parts[2]
  const region = parts[3]
  const account = parts[4]
  const resourcePart = parts.slice(5).join(':')
  const bucketNamePattern = resourcePart.split('/')[0]

  return (
    service === 's3' &&
    region === '' &&
    account === '' &&
    resourcePart.length > 0 &&
    bucketNamePattern.length > 0
  )
}
