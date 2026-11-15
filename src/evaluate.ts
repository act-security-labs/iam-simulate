import { type StatementAnalysis } from './StatementAnalysis.js'

/**
 * The result of evaluating policies that can grant or deny a request.
 */
export type EvaluationResult = 'Allowed' | 'ExplicitlyDenied' | 'ImplicitlyDenied'

/**
 * The result of evaluating identity policies. `NotApplicable` means identity policies cannot
 * apply to the request, such as for an AWS service principal.
 */
export type IdentityEvaluationResult = EvaluationResult | 'NotApplicable'

export type ResourceEvaluationResult =
  | 'NotApplicable'
  | 'Allowed'
  | 'ExplicitlyDenied'
  | 'AllowedForAccount'
  | 'DeniedForAccount'
  | 'ImplicitlyDenied'

export type BlockedReason = 'scp' | 'rcp' | 'vpce' | 'identity' | 'resource' | 'pb' | 's3-bpa'

export interface IdentityAnalysis {
  /**
   * The outcome of evaluating the identity-policy layer.
   */
  result: IdentityEvaluationResult
  denyStatements: StatementAnalysis[]
  allowStatements: StatementAnalysis[]
  unmatchedStatements: StatementAnalysis[]
}

export interface ResourceAnalysis {
  result: ResourceEvaluationResult
  denyStatements: StatementAnalysis[]
  allowStatements: StatementAnalysis[]
  unmatchedStatements: StatementAnalysis[]
}

export interface OuScpAnalysis {
  orgIdentifier: string
  result: EvaluationResult
  denyStatements: StatementAnalysis[]
  allowStatements: StatementAnalysis[]
  unmatchedStatements: StatementAnalysis[]
  conditions: AllowedConditionExpression
}

export interface ScpAnalysis {
  /**
   * OU Result
   */
  result: EvaluationResult
  ouAnalysis: OuScpAnalysis[]
  conditions: AllowedConditionExpression
}

export interface OuRcpAnalysis {
  orgIdentifier: string
  result: EvaluationResult
  denyStatements: StatementAnalysis[]
  allowStatements: StatementAnalysis[]
  unmatchedStatements: StatementAnalysis[]
  conditions: AllowedConditionExpression
}

export interface RcpAnalysis {
  /**
   * OU Result
   */
  result: EvaluationResult
  ouAnalysis: OuRcpAnalysis[]
  conditions: AllowedConditionExpression
}

export interface IgnoredCondition {
  op: string
  key: string
  values: string[]
}

/**
 * Conditions that were ignored during discovery mode.
 */
export type AllowedConditionExpression =
  | AlwaysAllowedCondition
  | NeverAllowedCondition
  | AllowedConditionGroup
  | AllowedConditionLeaf
  | AllowedSessionNameCondition

/** A condition expression that is always satisfied. */
export interface AlwaysAllowedCondition {
  conditionType: 'always'
}

/** A condition expression that cannot be satisfied. */
export interface NeverAllowedCondition {
  conditionType: 'never'
  reason: 'explicitDenyWithoutConditions' | 'noApplicableAllow'
}

/** A boolean grouping of allowed-condition expressions. */
export interface AllowedConditionGroup {
  conditionType: 'group'
  operator: 'and' | 'or'
  conditions: AllowedConditionExpression[]
}

/** A policy condition that must hold for access to be allowed. */
export interface AllowedConditionLeaf {
  conditionType: 'condition'
  op: string
  key: string
  values: string[]
  sources: AllowedConditionSource[]
  inverted?: true
}

/** A role session-name constraint that must hold for access to be allowed. */
export interface AllowedSessionNameCondition {
  conditionType: 'sessionName'
  sessionName: string[]
  sources: AllowedConditionSource[]
}

/** Metadata for the statement that contributed an allowed condition. */
export interface AllowedConditionSource {
  policyType:
    'session' | 'identity' | 'resource' | 'scp' | 'rcp' | 'permissionBoundary' | 'endpointPolicy'
  effect: 'Allow' | 'Deny'
  policyIdentifier?: string
  orgIdentifier?: string
  statementId?: string
  statementIndex: number
}

export interface IgnoredConditions {
  session?: {
    allow?: IgnoredCondition[]
    deny?: IgnoredCondition[]
  }
  scp?: {
    allow?: IgnoredCondition[]
    deny?: IgnoredCondition[]
  }
  rcp?: {
    allow?: IgnoredCondition[]
    deny?: IgnoredCondition[]
  }
  identity?: {
    allow?: IgnoredCondition[]
    deny?: IgnoredCondition[]
  }
  resource?: {
    allow?: IgnoredCondition[]
    deny?: IgnoredCondition[]
  }
  permissionBoundary?: {
    allow?: IgnoredCondition[]
    deny?: IgnoredCondition[]
  }
  endpointPolicy?: {
    allow?: IgnoredCondition[]
    deny?: IgnoredCondition[]
  }
}

/**
 * The analysis of a request.
 */
export interface RequestAnalysis {
  /**
   * The result of the evaluation.
   */
  result: EvaluationResult

  /**
   * Whether the principal and the resource are in the same account.
   */
  sameAccount: boolean

  /**
   * Set when the request can only be allowed with an Allow from the resource policy, because the
   * service does not implicitly trust the identity policies of the principal's account. This is the
   * case for cross-account and anonymous requests, principals without identity policies, and
   * resources such as KMS keys whose policy must delegate to IAM.
   *
   * Left unset when a service rule decides the request, since no policy can allow it.
   */
  resourceAllowRequired?: true

  /**
   * The result of the evaluation of the session policy, if any.
   */
  sessionAnalysis?: IdentityAnalysis | undefined

  /**
   * The result of the evaluation of the resource policy.
   */
  identityAnalysis?: IdentityAnalysis

  /**
   * The result of the evaluation of the resource policy.
   */
  resourceAnalysis?: ResourceAnalysis

  /**
   * The result of the evaluation of the SCPs
   */
  scpAnalysis?: ScpAnalysis

  /**
   * The result of the evaluation of the RCPs
   */
  rcpAnalysis?: RcpAnalysis

  /**
   * The result of the evaluation of the permission boundary.
   */
  permissionBoundaryAnalysis?: IdentityAnalysis | undefined

  /**
   * The result of the evaluation of the VPC endpoint policies, if any.
   */
  endpointAnalysis?: IdentityAnalysis | undefined

  /**
   * The conditions under which a Discovery-mode request is allowed.
   *
   * This is only present for final Allowed results when access depends on conditions
   * ignored because their request-context presence or value was unknown.
   */
  conditions?: AllowedConditionExpression

  /**
   * Any conditions that were ignored during discovery mode.
   */
  ignoredConditions?: IgnoredConditions

  /**
   * If the role session name was ignored during discovery mode.
   */
  ignoredRoleSessionName?: boolean

  /**
   * If the request has policies to allow the request in session, identity, and/or resource policies required, but was blocked
   * by another policy, this includes the policy types that blocked the request.
   *
   * It is possible for a request to have been allowed by the identity policy but blocked by the resource policy and vice versa.
   *
   * If this array is undefined or empty, it means that the core session, identity, and/or resource policies did
   * not grant permission. It does not mean that there are no guardrails in place, just that the request was
   * not allowed by the core policies, so there is no need to look for guardrails that block an otherwise allowed request.
   *
   * "Allowed by core policies" means that it would have been allowed if not for the policies identified in `blockedBy`. So
   * by removing the policies identified in `blockedBy`, the request would be allowed.
   *
   * Use this to discover what guardrails are in place that might block access even if it may be allowed by other policies.
   */
  blockedBy?: BlockedReason[]
}
