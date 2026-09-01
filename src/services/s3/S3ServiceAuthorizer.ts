import { isServicePrincipal } from '@actsecurity/iam-utils'
import { type RequestAnalysis } from '../../evaluate.js'
import { DefaultServiceAuthorizer } from '../DefaultServiceAuthorizer.js'
import { type ServiceAuthorizationRequest } from '../ServiceAuthorizer.js'
import { classifyS3RuntimePublicBucketPolicy } from './s3BlockPublicAccess.js'

/**
 * Service authorizer for S3 requests that applies S3 Block Public Access runtime behavior.
 */
export class S3ServiceAuthorizer extends DefaultServiceAuthorizer {
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
