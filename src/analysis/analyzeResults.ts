import {
  type BlockedReason,
  type EvaluationResult,
  type IdentityAnalysis,
  type RcpAnalysis,
  type RequestAnalysis,
  type ResourceAnalysis,
  type ScpAnalysis
} from '../evaluate.js'

/**
 * Analyze a RequestAnalysis to see if the request was allowed by identity policies.
 *
 * @param requestAnalysis the request analysis
 * @returns true if the request was allowed by identity policies, false otherwise
 */
export function isAllowedByIdentityPolicies(requestAnalysis: RequestAnalysis): boolean {
  const identityAnalysis = requestAnalysis.identityAnalysis
  if (!identityAnalysis) {
    return false
  }

  return identityAnalysis.result === 'Allowed'
}

export type DenialPolicyType = BlockedReason

export type RequestDenial =
  | {
      /**
       * The type of policy that caused the denial.
       */
      policyType: DenialPolicyType

      /**
       * This denial blocks a request that otherwise could have been allowed.
       */
      blocking?: true

      /**
       * The identifier of the policy that caused the denial, if applicable. This could be a
       * policy identifier or an organizational unit identifier for SCPs and RCPs.
       */
      identifier?: string

      /**
       * The type of denial.
       */
      denialType: 'Implicit'
    }
  | {
      /**
       * The type of policy that caused the denial.
       */
      policyType: DenialPolicyType

      /**
       * This denial blocks a request that otherwise could have been allowed.
       */
      blocking?: true

      /**
       * The identifier of the policy that caused the denial. May be undefined, for example
       * in a resource policy.
       */
      policyIdentifier?: string

      /**
       * The statement ID (Sid) of the denying policy statement, if present. This corresponds
       * to the Sid field in the AWS IAM policy statement and may be absent if the statement
       * does not define a Sid.
       */
      statementId?: string | undefined

      /**
       * The 1-based index of the denying statement within the policy, if applicable. This is useful when the statement does not have a Sid.
       */
      statementIndex: number

      /**
       * The type of denial.
       */
      denialType: 'Explicit'
    }
  | {
      /**
       * The type of policy that gave no Allow.
       */
      policyType: DenialPolicyType

      /**
       * This denial blocks a request that otherwise could have been allowed.
       */
      blocking?: true

      /**
       * The type of denial. The policy type gave no Allow because no policy of that type exists,
       * for example a request that needs a resource policy Allow on a resource that has none.
       */
      denialType: 'NotApplicable'
    }

export type RequestGrant =
  | {
      policyType: 'identity' | 'pb' | 'vpce'
      policyIdentifier: string
      statementId?: string | undefined
      statementIndex: number
    }
  | {
      policyType: 'resource'
      statementId?: string | undefined
      statementIndex: number
    }
  | {
      policyType: 'scp' | 'rcp'
      orgIdentifier: string
      policyIdentifier: string
      statementId?: string | undefined
      statementIndex: number
    }

/**
 * Find the policy statements that caused a request to be denied.
 * Analyzes the RequestAnalysis and returns the specific reasons why the request was denied.
 *
 * For an implicit denial, it returns:
 * - the policy type (identity, resource, scp, rcp, permission boundary, endpoint policy)
 * - the identifier, if applicable for an Organizational Unit identifier for SCPs.
 *
 * For an explicit denial, it returns:
 * - the policy type (identity, resource, scp, rcp, permission boundary, endpoint policy)
 * - the policy identifier, if applicable for a managed policy or an SCP
 * - the statement ID (Sid), if the denying statement has one
 * - the statement index (1-based) of the denying statement
 *
 * For a policy type that gave no Allow because no such policy exists, it returns the policy type
 * with a `NotApplicable` denial type. This is reported when the request needed an Allow from the
 * resource policy and the resource has no resource policy.
 *
 * @param requestAnalysis the request analysis
 * @returns a list of RequestDenial objects describing the reasons for denial
 */
export function getDenialReasons(requestAnalysis: RequestAnalysis): RequestDenial[] {
  const denials: RequestDenial[] = []
  const overallResult = requestAnalysis.result
  const blockedBy = new Set(requestAnalysis.blockedBy ?? [])

  addSimplePolicyDenials(
    requestAnalysis.identityAnalysis,
    'identity',
    overallResult,
    blockedBy,
    denials
  )
  addSimplePolicyDenials(
    requestAnalysis.resourceAnalysis,
    'resource',
    overallResult,
    blockedBy,
    denials
  )
  addMissingResourcePolicyDenial(requestAnalysis, denials)
  addOuPolicyDenials(requestAnalysis.scpAnalysis, 'scp', overallResult, blockedBy, denials)
  addOuPolicyDenials(requestAnalysis.rcpAnalysis, 'rcp', overallResult, blockedBy, denials)
  addSimplePolicyDenials(
    requestAnalysis.permissionBoundaryAnalysis,
    'pb',
    overallResult,
    blockedBy,
    denials
  )
  addSimplePolicyDenials(
    requestAnalysis.endpointAnalysis,
    'vpce',
    overallResult,
    blockedBy,
    denials
  )

  return denials
}

/**
 * Helper for identity-style policies (identity, resource, permissionBoundary, endpoint).
 * Adds denial reasons from a simple policy analysis.
 */
function addSimplePolicyDenials(
  analysis: IdentityAnalysis | ResourceAnalysis | undefined,
  policyType: DenialPolicyType,
  overallResult: EvaluationResult,
  blockedBy: Set<BlockedReason>,
  denials: RequestDenial[]
): void {
  if (!analysis) return

  const isBlocking = blockedBy.has(policyType)
  const blocking = isBlocking ? { blocking: true as const } : {}

  if (
    analysis.result === 'ImplicitlyDenied' &&
    (isBlocking || overallResult === 'ImplicitlyDenied')
  ) {
    denials.push({
      policyType,
      denialType: 'Implicit',
      ...blocking
    })
  } else if (
    analysis.result === 'ExplicitlyDenied' &&
    (isBlocking || overallResult === 'ExplicitlyDenied')
  ) {
    for (const stmt of analysis.denyStatements) {
      const sid = stmt.statement.sid()
      denials.push({
        policyType,
        ...blocking,
        policyIdentifier: stmt.policyId,
        ...(sid ? { statementId: sid } : {}),
        statementIndex: stmt.statement.index(),
        denialType: 'Explicit'
      })
    }
  }
}

/**
 * Adds a resource denial for a request that needed an Allow from the resource policy, on a resource
 * that has no resource policy.
 */
function addMissingResourcePolicyDenial(
  requestAnalysis: RequestAnalysis,
  denials: RequestDenial[]
): void {
  if (
    requestAnalysis.result === 'ImplicitlyDenied' &&
    requestAnalysis.resourceAllowRequired &&
    requestAnalysis.resourceAnalysis?.result === 'NotApplicable'
  ) {
    denials.push({ policyType: 'resource', denialType: 'NotApplicable' })
  }
}

/**
 * Helper for OU-based policies (scp, rcp).
 * Adds denial reasons from an organizational policy analysis.
 */
function addOuPolicyDenials(
  analysis: ScpAnalysis | RcpAnalysis | undefined,
  policyType: DenialPolicyType,
  overallResult: EvaluationResult,
  blockedBy: Set<BlockedReason>,
  denials: RequestDenial[]
): void {
  if (!analysis) return

  const isBlocking = blockedBy.has(policyType)
  const blocking = isBlocking ? { blocking: true as const } : {}

  if (
    analysis.result === 'ImplicitlyDenied' &&
    (isBlocking || overallResult === 'ImplicitlyDenied')
  ) {
    for (const ou of analysis.ouAnalysis) {
      if (ou.result === 'ImplicitlyDenied') {
        denials.push({
          policyType,
          identifier: ou.orgIdentifier,
          denialType: 'Implicit',
          ...blocking
        })
      }
    }
  } else if (
    analysis.result === 'ExplicitlyDenied' &&
    (isBlocking || overallResult === 'ExplicitlyDenied')
  ) {
    for (const ou of analysis.ouAnalysis) {
      if (ou.result === 'ExplicitlyDenied') {
        for (const stmt of ou.denyStatements) {
          const sid = stmt.statement.sid()
          denials.push({
            policyType,
            policyIdentifier: stmt.policyId,
            ...(sid ? { statementId: sid } : {}),
            statementIndex: stmt.statement.index(),
            ...blocking,
            denialType: 'Explicit'
          })
        }
      }
    }
  }
}

/**
 * Find the policy statements that granted access for an allowed request.
 * Analyzes the RequestAnalysis and returns the specific grants that allowed the request.
 *
 * @param requestAnalysis the request analysis
 * @returns a list of RequestGrant objects describing which policies granted access
 */
export function getGrantReasons(requestAnalysis: RequestAnalysis): RequestGrant[] {
  if (requestAnalysis.result !== 'Allowed') {
    return []
  }

  const grantDetails: RequestGrant[] = []

  addSimplePolicyGrants(requestAnalysis.identityAnalysis, 'identity', grantDetails)
  addSimplePolicyGrants(requestAnalysis.resourceAnalysis, 'resource', grantDetails)
  addSimplePolicyGrants(requestAnalysis.permissionBoundaryAnalysis, 'pb', grantDetails)
  addSimplePolicyGrants(requestAnalysis.endpointAnalysis, 'vpce', grantDetails)
  addOuPolicyGrants(requestAnalysis.scpAnalysis, 'scp', grantDetails)
  addOuPolicyGrants(requestAnalysis.rcpAnalysis, 'rcp', grantDetails)

  return grantDetails
}

/**
 * Helper for simple policy grants (identity, resource, pb, vpce).
 */
function addSimplePolicyGrants(
  analysis: IdentityAnalysis | ResourceAnalysis | undefined,
  policyType: 'identity' | 'resource' | 'pb' | 'vpce',
  grants: RequestGrant[]
): void {
  if (analysis?.result !== 'Allowed' && analysis?.result !== 'AllowedForAccount') return
  for (const stmt of analysis.allowStatements) {
    const sid = stmt.statement.sid()
    if (policyType === 'resource') {
      grants.push({
        policyType: 'resource',
        ...(sid ? { statementId: sid } : {}),
        statementIndex: stmt.statement.index()
      })
    } else {
      grants.push({
        policyType,
        policyIdentifier: stmt.policyId,
        ...(sid ? { statementId: sid } : {}),
        statementIndex: stmt.statement.index()
      })
    }
  }
}

/**
 * Helper for OU-based policy grants (scp, rcp).
 */
function addOuPolicyGrants(
  analysis: ScpAnalysis | RcpAnalysis | undefined,
  policyType: 'scp' | 'rcp',
  grants: RequestGrant[]
): void {
  if (!analysis) return
  for (const ou of analysis.ouAnalysis) {
    if (ou.result !== 'Allowed') continue
    for (const stmt of ou.allowStatements) {
      const sid = stmt.statement.sid()
      grants.push({
        policyType,
        orgIdentifier: ou.orgIdentifier,
        policyIdentifier: stmt.policyId,
        ...(sid ? { statementId: sid } : {}),
        statementIndex: stmt.statement.index()
      })
    }
  }
}
