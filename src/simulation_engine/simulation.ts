import { isCloudFrontOriginAccessUserArn } from '@actsecurity/iam-utils'

/**
 * Explicit marker for an unsigned anonymous request.
 */
export interface AnonymousRequestPrincipal {
  type: 'Anonymous'
}

/** A CloudFront OAI policy principal and its optional known S3 canonical user alias. */
export interface CloudFrontOriginAccessIdentityRequestPrincipal {
  type: 'CloudFrontOriginAccessIdentity'
  arn: string
  canonicalUserId?: string
}

/**
 * Principal value for a simulation request.
 */
export type SimulationRequestPrincipal =
  string | AnonymousRequestPrincipal | CloudFrontOriginAccessIdentityRequestPrincipal

/**
 * Convenience value for anonymous simulations.
 */
export const anonymousPrincipal: AnonymousRequestPrincipal = { type: 'Anonymous' }

/**
 * Checks whether a value is the anonymous request-principal marker.
 *
 * This guard intentionally accepts only the exact public anonymous shape so unsupported object fields
 * cannot be confused with future principal variants.
 *
 * @param value the value to check.
 * @returns true if the value is an anonymous request principal.
 */
export function isAnonymousRequestPrincipal(value: unknown): value is AnonymousRequestPrincipal {
  return (
    typeof value === 'object' &&
    value !== null &&
    !Array.isArray(value) &&
    Object.keys(value).length === 1 &&
    (value as { type?: unknown }).type === 'Anonymous'
  )
}

/**
 * Validate the OAI principal shape without inferring its canonical alias or owner.
 *
 * @param value the principal input
 * @returns whether the value is a valid OAI principal
 */
export function isCloudFrontOriginAccessIdentityRequestPrincipal(
  value: unknown
): value is CloudFrontOriginAccessIdentityRequestPrincipal {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return false
  }
  const principal = value as Record<string, unknown>
  return (
    Object.keys(principal).every((key) => ['type', 'arn', 'canonicalUserId'].includes(key)) &&
    principal.type === 'CloudFrontOriginAccessIdentity' &&
    typeof principal.arn === 'string' &&
    isCloudFrontOriginAccessUserArn(principal.arn) &&
    (!Object.hasOwn(principal, 'canonicalUserId') ||
      (typeof principal.canonicalUserId === 'string' && principal.canonicalUserId.length > 0))
  )
}

/**
 * Checks whether a value is a supported simulation request principal.
 *
 * @param value the value to check.
 * @returns true if the value is a string principal or the anonymous marker.
 */
export function isSimulationRequestPrincipal(value: unknown): value is SimulationRequestPrincipal {
  return (
    typeof value === 'string' ||
    isAnonymousRequestPrincipal(value) ||
    isCloudFrontOriginAccessIdentityRequestPrincipal(value)
  )
}

/**
 * Represents the policies attached to an OU, or account
 */
export interface SimulationOrgPolicies {
  orgIdentifier: string
  policies: { name: string; policy: any }[]
}

/**
 * Represent a policy attached to an identity
 */
export interface SimulationIdentityPolicy {
  name: string
  policy: any
}

export interface Simulation {
  request: {
    principal: SimulationRequestPrincipal
    action: string
    resource: {
      resource: string
      accountId: string
    }
    contextVariables: Record<string, string | string[]>
  }

  /**
   * A session policy, if any, for the current Role or Federated User session.
   */
  sessionPolicy?: any | undefined

  /**
   * The identity policies that are attached to the principal making the request
   */
  identityPolicies: SimulationIdentityPolicy[]

  /**
   * The service control policies that apply to the simulation.
   * The root OU should be the first element in the array.
   * The account specific SCPs should be the last element in the array.
   */
  serviceControlPolicies: SimulationOrgPolicies[]

  /**
   * The resource control policies for the simulation.
   * One per level of the OU/Account hierarchy.
   * The default Resource Control Policy, RCPFullAWSAccess, is automatically added to the simulation.
   */
  resourceControlPolicies: SimulationOrgPolicies[]

  /**
   * The resource policy, if any
   */
  resourcePolicy?: any

  /**
   * The permission boundary policies, if any.
   */
  permissionBoundaryPolicies?: { name: string; policy: any }[]

  /**
   * The VPC endpoint policies, if any.
   */
  vpcEndpointPolicies?: { name: string; policy: any }[]

  /**
   * Additional settings that may affect the simulation
   */
  additionalSettings?: {
    s3?: {
      /**
       * If an S3 bucket request, whether ABAC is enabled on the bucket
       */
      bucketAbacEnabled?: boolean

      /**
       * Caller-supplied effective S3 Block Public Access setting for RestrictPublicBuckets.
       * iam-simulate does not determine this value from AWS; callers must provide it.
       */
      blockPublicAccess?: boolean
    }
  }
}
