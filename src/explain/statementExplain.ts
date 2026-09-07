export type ExplainPrincipalMatch =
  'Match' | 'NoMatch' | 'AccountLevelMatch' | 'SessionRoleMatch' | 'SessionUserMatch'

export interface ActionExplain {
  action: string
  matches: boolean
}

/**
 * Known reasons that a policy resource can fail to match a request resource.
 *
 * The `invertible` flag records whether the mismatch definitively proves that
 * the request is outside a `NotResource` set. Non-invertible reasons indicate
 * invalid policy syntax or unavailable input rather than a definitive mismatch.
 */
export const resourceMismatchReasons = {
  invalidPolicyResourceArn: { invertible: false },
  requestMissingResource: { invertible: false },
  unresolvablePolicyVariable: { invertible: false },
  shortArnNoMatch: { invertible: true },
  // Expanded short ARN mismatches preserve existing conservative behavior and are not inverted.
  shortArnExpandedMismatch: { invertible: false },
  wildcardOnlyActionSpecificResource: { invertible: true },
  requestAllResourcesSpecificNotResource: { invertible: true },
  requestAllResourcesDenySpecificResource: { invertible: true },
  resourcePatternMismatch: { invertible: true },
  partitionMismatch: { invertible: true },
  serviceMismatch: { invertible: true },
  regionMismatch: { invertible: true },
  accountMismatch: { invertible: true },
  productMismatch: { invertible: true },
  resourceIdMismatch: { invertible: true }
} as const

/**
 * A machine-readable key explaining why a policy resource did not match a request resource.
 */
export type ResourceMismatchReason = keyof typeof resourceMismatchReasons

export interface ResourceExplain {
  resource: string
  resolvedValue?: string
  errors?: string[]
  /**
   * Machine-readable reason for a non-match, when the resource did not match.
   */
  mismatchReason?: ResourceMismatchReason
  matches: boolean
}

export interface PrincipalExplain {
  principal: string
  matches: ExplainPrincipalMatch
  roleForSessionArn?: string
  userForSessionArn?: string
  errors?: string[]
}

export interface ConditionValueExplain {
  value: string
  resolvedValue?: string
  matches: boolean
  matchingValues?: string[]
  negativeMatchingValues?: string[]
  errors?: string[]
}

export interface ConditionExplain {
  /**
   * The operation that was used in the condition statement
   */
  operator: string

  /**
   * The value being matched in the condition statement
   */
  conditionKeyValue: string

  /**
   * The resolved value of the condition key
   */
  resolvedConditionKeyValue?: string
  values: ConditionValueExplain | ConditionValueExplain[]

  /**
   * The values from the request context that were not matched by a condition with a set operation
   */
  unmatchedValues?: string[]

  /**
   * Whether the condition matches the request
   */
  matches: boolean

  /**
   * Matched because context key was missing from the request.
   */
  matchedBecauseMissing?: boolean

  /**
   * Failed because the context key was missing from the request.
   */
  failedBecauseMissing?: boolean

  /**
   * Failed because the context key was required to be a string but was was
   * an instead an array. Caused by a set operation being used on a single value
   * context key.
   */
  failedBecauseArray?: boolean

  /**
   * Was the base operator in the condition statement not found
   */
  missingOperator?: boolean
}

export interface StatementExplain {
  actionMatch: boolean
  resourceMatch: boolean
  principalMatch: ExplainPrincipalMatch
  conditionMatch: boolean

  matches: boolean
  identifier: string
  effect: string
  actions?: ActionExplain | ActionExplain[]
  notActions?: ActionExplain | ActionExplain[]
  resources?: ResourceExplain | ResourceExplain[]
  notResources?: ResourceExplain | ResourceExplain[]
  principals?: PrincipalExplain | PrincipalExplain[]
  notPrincipals?: PrincipalExplain | PrincipalExplain[]
  conditions?: ConditionExplain[]

  /**
   * The statement was denied because the resource policy has a NotPrincipal in a Deny
   * statement and the principal has a Permission Boundary.
   *
   * This will always resolve to to Deny.
   *
   * https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html
   */
  denyBecauseNpInRpAndPb?: boolean

  /**
   * The statement in a resource policy had neither a Principal nor a NotPrincipal
   * element. AWS accepts this syntactically, but such a statement can never match
   * a request, so the simulator reports it as NoMatch with this flag set.
   */
  noPrincipalElement?: boolean
}

/*
I want to emit the policy object exactly as it was written. How do I get a structure
that matches the policy object exactly? Should I just embed the values in the explain?
*/
