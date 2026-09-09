import { type Condition } from '@actsecurity/iam-policy'
import {
  type AllowedConditionExpression,
  type AllowedConditionLeaf,
  type AllowedConditionSource,
  type AllowedSessionNameCondition,
  type IdentityAnalysis,
  type RcpAnalysis,
  type ResourceAnalysis,
  type ScpAnalysis
} from '../evaluate.js'
import { type StatementAnalysis } from '../StatementAnalysis.js'

/**
 * Convert a statement's ignored allow-side conditions to an expression.
 *
 * @param statement the statement analysis to convert
 * @param policyType the policy family containing the statement
 * @param orgIdentifier the organization identifier for control-policy statements
 * @returns an expression for the statement's ignored conditions
 */
export function allowStatementExpression(
  statement: StatementAnalysis,
  policyType: AllowedConditionSource['policyType'],
  orgIdentifier?: string
): AllowedConditionExpression {
  return statementConditionExpression(statement, policyType, false, orgIdentifier)
}

/**
 * Convert a statement's ignored deny-side conditions to an expression that avoids the deny.
 *
 * @param statement the statement analysis to convert
 * @param policyType the policy family containing the statement
 * @param orgIdentifier the organization identifier for control-policy statements
 * @returns an expression that must hold to avoid the deny
 */
export function denyStatementEscapeExpression(
  statement: StatementAnalysis,
  policyType: AllowedConditionSource['policyType'],
  orgIdentifier?: string
): AllowedConditionExpression {
  if (!statement.ignoredConditions || statement.ignoredConditions.length === 0) {
    return never('explicitDenyWithoutConditions')
  }

  const source = sourceForStatement(statement, policyType, orgIdentifier)
  return or(statement.ignoredConditions.map((condition) => invertCondition(condition, source)))
}

/**
 * Invert a single IAM condition into an allowed-condition expression.
 *
 * @param condition the condition to invert
 * @param source source metadata for the condition
 * @returns the expression that satisfies the logical complement of the condition
 */
export function invertCondition(
  condition: Condition,
  source: AllowedConditionSource
): AllowedConditionExpression {
  const op = condition.operation().value()
  const key = condition.conditionKey()
  const values = condition.conditionValues()
  return invertConditionParts(op, key, values, source)
}

/**
 * Combine condition expressions with AND semantics and simplify identity/absorbing values.
 *
 * @param expressions the expressions to combine
 * @returns a simplified expression
 */
export function and(expressions: AllowedConditionExpression[]): AllowedConditionExpression {
  const children = expressions.map((expr) => simplify(expr))
  if (children.some((expr) => expr.conditionType === 'never')) {
    return children.find((expr) => expr.conditionType === 'never')!
  }
  const withoutAlways = dedupe(
    children
      .filter((expr) => expr.conditionType !== 'always')
      .flatMap((expr) =>
        expr.conditionType === 'group' && expr.operator === 'and' ? expr.conditions : [expr]
      )
  )
  if (withoutAlways.length === 0) {
    return always()
  }
  if (withoutAlways.length === 1) {
    return withoutAlways[0]
  }
  return { conditionType: 'group', operator: 'and', conditions: withoutAlways }
}

/**
 * Combine condition expressions with OR semantics and simplify identity/absorbing values.
 *
 * @param expressions the expressions to combine
 * @returns a simplified expression
 */
export function or(expressions: AllowedConditionExpression[]): AllowedConditionExpression {
  const children = expressions.map((expr) => simplify(expr))
  if (children.some((expr) => expr.conditionType === 'always')) {
    return always()
  }
  const withoutNever = dedupe(
    children
      .filter((expr) => expr.conditionType !== 'never')
      .flatMap((expr) =>
        expr.conditionType === 'group' && expr.operator === 'or' ? expr.conditions : [expr]
      )
  )
  if (withoutNever.length === 0) {
    return never('noApplicableAllow')
  }
  if (withoutNever.length === 1) {
    return withoutNever[0]
  }
  return { conditionType: 'group', operator: 'or', conditions: withoutNever }
}

export function allowedConditionOutput(
  expression: AllowedConditionExpression,
  simulationMode: string,
  result: string
): AllowedConditionExpression | undefined {
  if (simulationMode !== 'Discovery' || result !== 'Allowed') {
    return undefined
  }
  return publicExpression(expression)
}

/**
 * Merge condition expressions that must all be satisfied and reduce the public result.
 *
 * Undefined expressions are ignored. The remaining expressions are combined with AND semantics,
 * simplified through the existing condition reducers, and converted to the public condition shape
 * where unconditional or impossible expressions are omitted.
 *
 * @param expressions the optional condition expressions to merge
 * @returns the reduced merged condition expression, or undefined when no public condition remains
 */
export function mergeAllowedConditionExpressions(
  expressions: Array<AllowedConditionExpression | undefined>
): AllowedConditionExpression | undefined {
  return publicExpression(
    and(expressions.filter((expr): expr is AllowedConditionExpression => !!expr))
  )
}

export function sessionPolicyExpression(
  analysis: IdentityAnalysis | undefined,
  sessionPolicyPresent: boolean
): AllowedConditionExpression {
  return sessionPolicyPresent ? identityAllowExpression(analysis, 'session') : always()
}

export function identityPolicyExpression(
  analysis: IdentityAnalysis | undefined
): AllowedConditionExpression {
  return identityAllowExpression(analysis, 'identity')
}

export function permissionBoundaryExpression(
  analysis: IdentityAnalysis | undefined
): AllowedConditionExpression {
  return identityAllowExpression(analysis, 'permissionBoundary')
}

export function endpointPolicyExpression(
  analysis: IdentityAnalysis | undefined
): AllowedConditionExpression {
  return identityAllowExpression(analysis, 'endpointPolicy')
}

export function resourceAllowStatementsExpression(
  statements: StatementAnalysis[]
): AllowedConditionExpression {
  return allowStatementsExpression(statements, 'resource')
}

export function allDenyEscapeExpressions(input: {
  sessionAnalysis?: IdentityAnalysis
  scpAnalysis?: ScpAnalysis
  rcpAnalysis?: RcpAnalysis
  identityAnalysis?: IdentityAnalysis
  resourceAnalysis?: ResourceAnalysis
  permissionBoundaryAnalysis?: IdentityAnalysis
  endpointAnalysis?: IdentityAnalysis
}): AllowedConditionExpression[] {
  return [
    ...denyEscapeExpressions(input.sessionAnalysis, 'session'),
    ...controlPolicyDenyEscapeExpressions(input.scpAnalysis, 'scp'),
    ...controlPolicyDenyEscapeExpressions(input.rcpAnalysis, 'rcp'),
    ...denyEscapeExpressions(input.identityAnalysis, 'identity'),
    ...resourceDenyEscapeExpressions(input.resourceAnalysis),
    ...denyEscapeExpressions(input.permissionBoundaryAnalysis, 'permissionBoundary'),
    ...denyEscapeExpressions(input.endpointAnalysis, 'endpointPolicy')
  ]
}

function identityAllowExpression(
  analysis: IdentityAnalysis | undefined,
  policyType: AllowedConditionSource['policyType']
): AllowedConditionExpression {
  if (!analysis || analysis.result !== 'Allowed') {
    return never('noApplicableAllow')
  }
  return allowStatementsExpression(analysis.allowStatements, policyType)
}

function allowStatementsExpression(
  statements: StatementAnalysis[],
  policyType: AllowedConditionSource['policyType']
): AllowedConditionExpression {
  if (statements.length === 0) {
    return never('noApplicableAllow')
  }
  return or(statements.map((statement) => allowStatementExpression(statement, policyType)))
}

function denyEscapeExpressions(
  analysis: IdentityAnalysis | undefined,
  policyType: AllowedConditionSource['policyType']
): AllowedConditionExpression[] {
  return denyStatementsThatNeedEscapes(analysis).map((statement) =>
    denyStatementEscapeExpression(statement, policyType)
  )
}

function resourceDenyEscapeExpressions(
  analysis: ResourceAnalysis | undefined
): AllowedConditionExpression[] {
  return denyStatementsThatNeedEscapes(analysis).map((statement) =>
    denyStatementEscapeExpression(statement, 'resource')
  )
}

function controlPolicyDenyEscapeExpressions(
  analysis: ScpAnalysis | RcpAnalysis | undefined,
  policyType: 'scp' | 'rcp'
): AllowedConditionExpression[] {
  return (analysis?.ouAnalysis ?? []).flatMap((ou) =>
    denyStatementsThatNeedEscapes(ou).map((statement) =>
      denyStatementEscapeExpression(statement, policyType, ou.orgIdentifier)
    )
  )
}

function denyStatementsThatNeedEscapes(
  analysis:
    { denyStatements: StatementAnalysis[]; unmatchedStatements: StatementAnalysis[] } | undefined
): StatementAnalysis[] {
  return [...(analysis?.denyStatements ?? []), ...(analysis?.unmatchedStatements ?? [])].filter(
    (statement) => statement.statement.isDeny() && (statement.ignoredConditions?.length ?? 0) > 0
  )
}

function statementConditionExpression(
  statement: StatementAnalysis,
  policyType: AllowedConditionSource['policyType'],
  inverted: boolean,
  orgIdentifier?: string
): AllowedConditionExpression {
  const source = sourceForStatement(statement, policyType, orgIdentifier)
  const conditions = statement.ignoredConditions ?? []
  const conditionExpressions: AllowedConditionExpression[] = conditions.map((condition) =>
    conditionLeaf(condition, source, inverted)
  )
  const sessionExpression = sessionNameExpression(statement, source)
  if (sessionExpression) {
    conditionExpressions.push(sessionExpression)
  }
  return and(conditionExpressions)
}

function sourceForStatement(
  statement: StatementAnalysis,
  policyType: AllowedConditionSource['policyType'],
  orgIdentifier?: string
): AllowedConditionSource {
  const sid = statement.statement.sid()
  return {
    policyType,
    effect: statement.statement.effect() as 'Allow' | 'Deny',
    policyIdentifier: statement.policyId,
    ...(orgIdentifier ? { orgIdentifier } : {}),
    ...(sid ? { statementId: sid } : {}),
    statementIndex: statement.statement.index()
  }
}

function conditionLeaf(
  condition: Condition,
  source: AllowedConditionSource,
  inverted: boolean
): AllowedConditionLeaf {
  return {
    conditionType: 'condition',
    op: condition.operation().value(),
    key: condition.conditionKey(),
    values: condition.conditionValues(),
    sources: [source],
    ...(inverted ? { inverted: true as const } : {})
  }
}

function sessionNameExpression(
  statement: StatementAnalysis,
  source: AllowedConditionSource
): AllowedSessionNameCondition | undefined {
  if (!statement.ignoredRoleSessionName) {
    return undefined
  }

  const names = principalExplains(statement)
    .map((explain) => sessionNameFromAssumedRoleArn(explain.principal))
    .filter((name): name is string => name !== undefined)

  if (names.length === 0) {
    return undefined
  }

  return {
    conditionType: 'sessionName',
    sessionName: Array.from(new Set(names)),
    sources: [source]
  }
}

function principalExplains(statement: StatementAnalysis): { principal: string }[] {
  const principals = statement.explain.principals ?? statement.explain.notPrincipals
  if (!principals) {
    return []
  }
  return Array.isArray(principals) ? principals : [principals]
}

function sessionNameFromAssumedRoleArn(arn: string): string | undefined {
  const resource = arn.split(':').at(-1)
  if (!resource?.startsWith('assumed-role/')) {
    return undefined
  }
  return resource.split('/').at(2)
}

function invertConditionParts(
  op: string,
  key: string,
  values: string[],
  source: AllowedConditionSource
): AllowedConditionExpression {
  const setOperator = conditionSetOperator(op)
  const hasIfExists = isIfExists(op)
  const base = conditionBaseOperator(op)

  if (hasIfExists) {
    const withoutIfExists = operatorName(base, setOperator, false)
    const invertedBase = invertConditionParts(withoutIfExists, key, values, source)
    if (negativeConditionOperatorsMatchMissingKeys(base)) {
      return invertedBase
    }
    return and([leaf('Null', key, ['false'], source), invertedBase])
  }

  if (base.toLowerCase() === 'null' || base.toLowerCase() === 'bool') {
    return leaf(
      invertedOperatorName(op, base, setOperator, hasIfExists),
      key,
      flipBooleanValues(values),
      source
    )
  }

  if (setOperator === 'ForAllValues') {
    return and([
      leaf('Null', key, ['false'], source),
      leaf(operatorName(invertBaseOperator(base), 'ForAnyValue', false), key, values, source)
    ])
  }

  if (setOperator === 'ForAnyValue') {
    return or([
      leaf('Null', key, ['true'], source),
      leaf(operatorName(invertBaseOperator(base), 'ForAllValues', false), key, values, source)
    ])
  }

  return leaf(invertBaseOperator(base), key, values, source)
}

function leaf(
  op: string,
  key: string,
  values: string[],
  source: AllowedConditionSource
): AllowedConditionLeaf {
  return {
    conditionType: 'condition',
    op,
    key,
    values,
    sources: [source],
    inverted: true
  }
}

function conditionSetOperator(op: string): 'ForAllValues' | 'ForAnyValue' | undefined {
  const prefix = op.includes(':') ? op.split(':')[0].toLowerCase() : undefined
  if (prefix === 'forallvalues') {
    return 'ForAllValues'
  }
  if (prefix === 'foranyvalue') {
    return 'ForAnyValue'
  }
  return undefined
}

function conditionBaseOperator(op: string): string {
  return op
    .split(':')
    .at(-1)!
    .replace(/IfExists$/i, '')
}

function isIfExists(op: string): boolean {
  return /IfExists$/i.test(op)
}

function invertedOperatorName(
  originalOp: string,
  base: string,
  setOperator: 'ForAllValues' | 'ForAnyValue' | undefined,
  hasIfExists: boolean
): string {
  if (base.toLowerCase() === 'bool' || base.toLowerCase() === 'null') {
    return operatorName(base, setOperator, hasIfExists)
  }
  return originalOp
}

function negativeConditionOperatorsMatchMissingKeys(base: string): boolean {
  return new Set([
    'stringnotequals',
    'stringnotequalsignorecase',
    'stringnotlike',
    'arnnotequals',
    'arnnotlike',
    'numericnotequals',
    'datenotequals',
    'notipaddress',
    'binarynotequals'
  ]).has(base.toLowerCase())
}

function operatorName(
  base: string,
  setOperator: 'ForAllValues' | 'ForAnyValue' | undefined,
  ifExists: boolean
): string {
  const op = canonicalBaseOperator(base) + (ifExists ? 'IfExists' : '')
  return setOperator ? `${setOperator}:${op}` : op
}

function invertBaseOperator(base: string): string {
  const map: Record<string, string> = {
    stringequals: 'StringNotEquals',
    stringnotequals: 'StringEquals',
    stringequalsignorecase: 'StringNotEqualsIgnoreCase',
    stringnotequalsignorecase: 'StringEqualsIgnoreCase',
    stringlike: 'StringNotLike',
    stringnotlike: 'StringLike',
    arnequals: 'ArnNotEquals',
    arnnotequals: 'ArnEquals',
    arnlike: 'ArnNotLike',
    arnnotlike: 'ArnLike',
    numericequals: 'NumericNotEquals',
    numericnotequals: 'NumericEquals',
    numericlessthan: 'NumericGreaterThanEquals',
    numericlessthanequals: 'NumericGreaterThan',
    numericgreaterthan: 'NumericLessThanEquals',
    numericgreaterthanequals: 'NumericLessThan',
    dateequals: 'DateNotEquals',
    datenotequals: 'DateEquals',
    datelessthan: 'DateGreaterThanEquals',
    datelessthanequals: 'DateGreaterThan',
    dategreaterthan: 'DateLessThanEquals',
    dategreaterthanequals: 'DateLessThan',
    ipaddress: 'NotIpAddress',
    notipaddress: 'IpAddress',
    binaryequals: 'BinaryNotEquals',
    binarynotequals: 'BinaryEquals'
  }
  return map[base.toLowerCase()] ?? `Not:${base}`
}

function canonicalBaseOperator(base: string): string {
  const canonical: Record<string, string> = {
    stringequals: 'StringEquals',
    stringnotequals: 'StringNotEquals',
    stringequalsignorecase: 'StringEqualsIgnoreCase',
    stringnotequalsignorecase: 'StringNotEqualsIgnoreCase',
    stringlike: 'StringLike',
    stringnotlike: 'StringNotLike',
    arnequals: 'ArnEquals',
    arnnotequals: 'ArnNotEquals',
    arnlike: 'ArnLike',
    arnnotlike: 'ArnNotLike',
    numericequals: 'NumericEquals',
    numericnotequals: 'NumericNotEquals',
    numericlessthan: 'NumericLessThan',
    numericlessthanequals: 'NumericLessThanEquals',
    numericgreaterthan: 'NumericGreaterThan',
    numericgreaterthanequals: 'NumericGreaterThanEquals',
    dateequals: 'DateEquals',
    datenotequals: 'DateNotEquals',
    datelessthan: 'DateLessThan',
    datelessthanequals: 'DateLessThanEquals',
    dategreaterthan: 'DateGreaterThan',
    dategreaterthanequals: 'DateGreaterThanEquals',
    bool: 'Bool',
    null: 'Null',
    ipaddress: 'IpAddress',
    notipaddress: 'NotIpAddress',
    binaryequals: 'BinaryEquals',
    binarynotequals: 'BinaryNotEquals'
  }
  return canonical[base.toLowerCase()] ?? base
}

function flipBooleanValues(values: string[]): string[] {
  return values.map((value) => (value.toLowerCase() === 'true' ? 'false' : 'true'))
}

function publicExpression(
  expression: AllowedConditionExpression
): AllowedConditionExpression | undefined {
  const simplified = simplify(expression)
  return simplified.conditionType === 'always' || simplified.conditionType === 'never'
    ? undefined
    : simplified
}

function simplify(expression: AllowedConditionExpression): AllowedConditionExpression {
  if (expression.conditionType !== 'group') {
    return expression
  }
  return expression.operator === 'and' ? and(expression.conditions) : or(expression.conditions)
}

export function always(): AllowedConditionExpression {
  return { conditionType: 'always' }
}

export function never(
  reason: 'explicitDenyWithoutConditions' | 'noApplicableAllow'
): AllowedConditionExpression {
  return { conditionType: 'never', reason }
}

function dedupe(expressions: AllowedConditionExpression[]): AllowedConditionExpression[] {
  const seen = new Set<string>()
  const result: AllowedConditionExpression[] = []
  for (const expression of expressions) {
    const key = JSON.stringify(expression)
    if (!seen.has(key)) {
      seen.add(key)
      result.push(expression)
    }
  }
  return result
}
