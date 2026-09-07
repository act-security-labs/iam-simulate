import { type Condition } from '@actsecurity/iam-policy'
import { type SimulationParameters } from '../core_engine/CoreSimulatorEngine.js'
import {
  type ConditionExplain,
  type ConditionValueExplain,
  type StatementExplain
} from '../explain/statementExplain.js'
import { type AwsRequest } from '../request/request.js'
import { type ContextKey, ContextKeyImpl } from '../requestContext.js'
import { ArnEquals } from './arn/ArnEquals.js'
import { ArnLike } from './arn/ArnLike.js'
import { ArnNotEquals } from './arn/ArnNotEquals.js'
import { ArnNotLike } from './arn/ArnNotLike.js'
import { type BaseConditionOperator } from './BaseConditionOperator.js'
import { BinaryEquals } from './binary/BinaryEquals.js'
import { Bool } from './boolean/Bool.js'
import { DateEquals } from './date/DateEquals.js'
import { DateGreaterThan } from './date/DateGreaterThan.js'
import { DateGreaterThanEquals } from './date/DateGreaterThanEquals.js'
import { DateLessThan } from './date/DateLessThan.js'
import { DateLessThanEquals } from './date/DateLessThanEquals.js'
import { DateNotEquals } from './date/DateNotEquals.js'
import { IpAddress } from './ipaddress/IpAddress.js'
import { NotIpAddress } from './ipaddress/NotIpAddress.js'
import { NumericEquals } from './numeric/NumericEquals.js'
import { NumericGreaterThan } from './numeric/NumericGreaterThan.js'
import { NumericGreaterThanEquals } from './numeric/NumericGreaterThanEquals.js'
import { NumericLessThan } from './numeric/NumericLessThan.js'
import { NumericLessThanEquals } from './numeric/NumericLessThanEquals.js'
import { NumericNotEquals } from './numeric/NumericNotEquals.js'
import { StringEquals } from './string/StringEquals.js'
import { StringEqualsIgnoreCase } from './string/StringEqualsIgnoreCase.js'
import { StringLike } from './string/StringLike.js'
import { StringNotEquals } from './string/StringNotEquals.js'
import { StringNotEqualsIgnoreCase } from './string/StringNotEqualsIgnoreCase.js'
import { StringNotLike } from './string/StringNotLike.js'

export type ConditionMatchResult = 'Match' | 'NoMatch'

const allOperators = [
  StringEquals,
  StringNotEquals,
  StringEqualsIgnoreCase,
  StringNotEqualsIgnoreCase,
  StringLike,
  StringNotLike,
  NumericEquals,
  NumericNotEquals,
  NumericLessThan,
  NumericLessThanEquals,
  NumericGreaterThan,
  NumericGreaterThanEquals,
  DateEquals,
  DateNotEquals,
  DateLessThan,
  DateLessThanEquals,
  DateGreaterThan,
  DateGreaterThanEquals,
  Bool,
  BinaryEquals,
  IpAddress,
  NotIpAddress,
  ArnLike,
  ArnEquals,
  ArnNotLike,
  ArnNotEquals
]

const baseOperations: { [key: string]: BaseConditionOperator } = {}
for (const operator of allOperators) {
  baseOperations[operator.name.toLowerCase()] = operator
}

/** A two-state marker for whether a fact is known during condition evaluation. */
type DiscoveryKnowledgeState = 'known' | 'unknown'

/**
 * Internal Discovery-mode knowledge state for a condition evaluation.
 *
 * This is deliberately not exposed in `ConditionExplain`. It keeps the request
 * context-key facts separate from the downstream question of whether the whole
 * condition result is known. For example, a missing key can have known presence
 * and no applicable value, while a present key can have known presence but an
 * unknown concrete value.
 */
interface DiscoveryConditionKnowledge {
  /** Whether the condition's true/false result can be determined from known facts. */
  conditionResult: DiscoveryKnowledgeState

  /** Whether the request context definitively proves the condition key is present or absent. */
  contextKeyPresence: DiscoveryKnowledgeState

  /**
   * Whether the condition key's concrete value is known.
   *
   * This is `not-applicable` when the condition key is known to be absent,
   * because there is no concrete value to know.
   */
  contextKeyValue: DiscoveryKnowledgeState | 'not-applicable'
}

/**
 * Internal Discovery-mode knowledge about the request context key used by a condition.
 *
 * This deliberately does not say whether the condition result is known. Operator
 * semantics decide that after the appropriate condition evaluator runs.
 */
type DiscoveryContextKeyKnowledge = Omit<DiscoveryConditionKnowledge, 'conditionResult'>

/**
 * Internal result for evaluating one condition before statement-type rules are applied.
 */
interface InternalConditionEvaluation {
  /** Existing public explain shape for the condition evaluation. */
  explain: ConditionExplain
  /** Internal Discovery knowledge used to decide whether to report a conditional result. */
  knowledge: DiscoveryConditionKnowledge
}

/**
 * A policy condition paired with its explain output and internal Discovery knowledge.
 */
interface ConditionAndExplain {
  /** The original policy condition. */
  condition: Condition
  /** Existing public explain shape for the condition evaluation. */
  explain: ConditionExplain
  /** Internal Discovery knowledge used for ignored-condition handling. */
  knowledge: DiscoveryConditionKnowledge
}

/**
 * Evaluate a set of conditions against a request
 *
 * @param request the request to test
 * @param conditions the conditions to test
 * @returns Match if all conditions match, NoMatch if any do not. Also returns all the details of the evaluation
 */
export function requestMatchesConditions(
  request: AwsRequest,
  conditions: Condition[],
  statementType: 'Allow' | 'Deny',
  simulationParameters: SimulationParameters
): {
  matches: ConditionMatchResult
  details: Pick<StatementExplain, 'conditions'>
  ignoredConditions?: Condition[]
} {
  const normalizedStatementType = statementType.toLowerCase() as 'allow' | 'deny'

  const results = conditions.map((condition) => {
    const evaluation = evaluateSingleCondition(request, condition, simulationParameters)
    return {
      condition,
      explain: evaluation.explain,
      knowledge: evaluation.knowledge
    }
  })

  const isIgnored = (c: ConditionAndExplain): boolean => {
    if (simulationParameters.simulationMode !== 'Discovery') {
      return false
    }

    const constraint = simulationParameters.discoveryContextKeyConstraints.constraintFor(
      c.condition.conditionKey()
    )
    if (c.knowledge.conditionResult !== 'known') {
      if (normalizedStatementType === 'allow') {
        return (
          !c.explain.matches ||
          allowHasUnknownPresenceRequirement(c) ||
          allowHasUnknownValueRequirement(c)
        )
      }
      if (normalizedStatementType === 'deny') {
        return true
      }
    }

    if (constraint.explicitlyConfigured) {
      return false
    }

    // In Allows we ignore conditions that do not match
    if (normalizedStatementType === 'allow') {
      return !c.explain.matches
    }
    // In Denies we ignore conditions that do match
    if (normalizedStatementType === 'deny') {
      return c.explain.matches
    }
    throw new Error(
      `Unexpected condition explain result in discovery mode, statementType: ${statementType}`
    )
  }

  const ignored = results.filter((r) => isIgnored(r))
  const nonMatch = results.filter((r) => !isIgnored(r)).some((result) => !result.explain.matches)
  const ignoredPossibleDeny =
    normalizedStatementType === 'deny' &&
    ignored.some((result) => result.knowledge.conditionResult !== 'known' || result.explain.matches)

  return {
    matches: nonMatch || ignoredPossibleDeny ? 'NoMatch' : ('Match' as ConditionMatchResult),
    details: {
      conditions: results.length == 0 ? undefined : results.map((r) => r.explain)
    },
    //Ignored conditions only matter if the non ignored fields all match
    ignoredConditions: nonMatch ? undefined : ignoredConditions(results, isIgnored)
  }
}

/**
 * Get the list of conditions that were ignored during discovery mode, if any
 *
 * @param conditions the conditions that were evaluated with their explains
 * @param statementType whether the statement is an allow or deny statement
 * @param simulationParameters the general parameters for the simulation
 * @returns an array of ignored conditions, or undefined if there are none
 */
function ignoredConditions(
  conditions: ConditionAndExplain[],
  isIgnored: (c: ConditionAndExplain) => boolean
): Condition[] | undefined {
  const ignoredConditions = conditions.filter(isIgnored)
  if (ignoredConditions.length > 0) {
    return ignoredConditions.map((r) => r.condition)
  }

  return undefined
}

/**
 * Checks to see if a single condition matches a request
 *
 * @param request the request to test
 * @param condition the condition to test
 * @returns the result of evaluating the condition
 */
export function singleConditionMatchesRequest(
  request: AwsRequest,
  condition: Condition,
  simulationParameters: SimulationParameters
): ConditionExplain {
  return evaluateSingleCondition(request, condition, simulationParameters).explain
}

/**
 * Evaluates a single condition and records internal Discovery knowledge.
 *
 * @param request the request to test
 * @param condition the condition to evaluate
 * @param simulationParameters the simulation mode and Discovery constraints
 * @returns the condition explain output plus internal Discovery knowledge
 */
function evaluateSingleCondition(
  request: AwsRequest,
  condition: Condition,
  simulationParameters: SimulationParameters
): InternalConditionEvaluation {
  const key = condition.conditionKey()
  const baseOperation = baseOperations[condition.operation().baseOperator().toLowerCase()]
  const keyExists = request.contextKeyExists(key)
  const keyValue = keyExists ? request.getContextKeyValue(key) : undefined
  const contextKeyKnowledge = discoveryKnowledgeForConditionKey(
    simulationParameters,
    condition.conditionKey(),
    keyExists
  )

  if (condition.operation().value().toLowerCase() == 'null') {
    return {
      explain: testNull(condition, keyExists),
      knowledge: conditionKnowledgeForPresenceOnly(contextKeyKnowledge)
    }
  }

  if (condition.operation().setOperator()) {
    const setOperator = condition.operation().setOperator()
    if (setOperator === 'ForAnyValue') {
      return {
        explain: forAnyValueMatch(request, condition, keyValue, baseOperation),
        knowledge: conditionKnowledgeForValueEvaluation(
          request,
          condition,
          simulationParameters,
          contextKeyKnowledge
        )
      }
    } else if (setOperator === 'ForAllValues') {
      return {
        explain: forAllValuesMatch(request, condition, keyValue, baseOperation),
        knowledge: conditionKnowledgeForValueEvaluation(
          request,
          condition,
          simulationParameters,
          contextKeyKnowledge
        )
      }
    } else {
      throw new Error(`Unknown set operator: ${setOperator}`)
    }
  }

  return {
    explain: singleValueMatch(request, condition, baseOperation, keyValue),
    knowledge: conditionKnowledgeForValueEvaluation(
      request,
      condition,
      simulationParameters,
      contextKeyKnowledge
    )
  }
}

/**
 * Determines what request context-key facts are known for a condition key.
 *
 * This function intentionally does not know about operators such as `Null`,
 * `IfExists`, `ForAnyValue`, or `ForAllValues`. It only answers whether the
 * request context definitively establishes key presence and value. Operator
 * evaluators decide how those facts affect the condition result.
 *
 * @param simulationParameters the simulation mode and Discovery constraints
 * @param key the condition context key to classify
 * @param keyExists whether the condition key exists in the request context
 * @returns Discovery knowledge about the condition's context key
 */
function discoveryKnowledgeForConditionKey(
  simulationParameters: SimulationParameters,
  key: string,
  keyExists: boolean
): DiscoveryContextKeyKnowledge {
  if (simulationParameters.simulationMode !== 'Discovery') {
    return requestContextKeyKnowledge(keyExists)
  }

  const constraint = simulationParameters.discoveryContextKeyConstraints.constraintFor(key)
  if (!constraint.explicitlyConfigured) {
    return keyExists ? requestContextKeyKnowledge(keyExists) : unknownContextKeyKnowledge()
  }

  const contextKeyPresence: DiscoveryKnowledgeState = constraint.presenceIsKnown
    ? 'known'
    : 'unknown'

  return {
    contextKeyPresence,
    contextKeyValue: contextValueKnowledge(keyExists, contextKeyPresence, constraint.valueIsKnown)
  }
}

/**
 * Derives condition-result knowledge for operators that only depend on key presence.
 *
 * `Null` conditions are evaluated by `testNull`; this helper only records that
 * their result is known exactly when key presence is known.
 *
 * @param contextKeyKnowledge known facts about the condition context key
 * @returns condition knowledge for a presence-only operator
 */
function conditionKnowledgeForPresenceOnly(
  contextKeyKnowledge: DiscoveryContextKeyKnowledge
): DiscoveryConditionKnowledge {
  return {
    conditionResult: contextKeyKnowledge.contextKeyPresence,
    ...contextKeyKnowledge
  }
}

/**
 * Derives condition-result knowledge for operators whose result may depend on value.
 *
 * Single-value, `IfExists`, `ForAnyValue`, and `ForAllValues` evaluators handle
 * their own missing-key semantics. Once those evaluators run, the result is
 * known when key presence is known and any required concrete values or policy
 * variable references are known.
 *
 * @param request the request being evaluated
 * @param condition the condition whose policy values may contain variables
 * @param simulationParameters the simulation mode and Discovery constraints
 * @param contextKeyKnowledge known facts about the condition context key
 * @returns condition knowledge for a value-capable operator
 */
function conditionKnowledgeForValueEvaluation(
  request: AwsRequest,
  condition: Condition,
  simulationParameters: SimulationParameters,
  contextKeyKnowledge: DiscoveryContextKeyKnowledge
): DiscoveryConditionKnowledge {
  if (contextKeyKnowledge.contextKeyPresence === 'unknown') {
    return { conditionResult: 'unknown', ...contextKeyKnowledge }
  }

  if (contextKeyKnowledge.contextKeyValue === 'unknown') {
    return { conditionResult: 'unknown', ...contextKeyKnowledge }
  }

  if (conditionValuesReferenceUnknownValue(request, condition, simulationParameters)) {
    return { conditionResult: 'unknown', ...contextKeyKnowledge }
  }

  return { conditionResult: 'known', ...contextKeyKnowledge }
}

/**
 * Builds context-key knowledge for normal request-context semantics.
 *
 * Outside explicitly configured Discovery constraints, the request context is
 * authoritative: key presence is known, and the value is known when present.
 *
 * @param keyExists whether the condition key exists in the request context
 * @returns context-key knowledge for ordinary request-context evaluation
 */
function requestContextKeyKnowledge(keyExists: boolean): DiscoveryContextKeyKnowledge {
  return {
    contextKeyPresence: 'known',
    contextKeyValue: keyExists ? 'known' : 'not-applicable'
  }
}

/**
 * Builds context-key knowledge for an absent unconstrained Discovery key.
 *
 * In Discovery mode, an absent synthetic request-context value does not prove
 * that the real request context lacks an unconstrained key.
 *
 * @returns context-key knowledge with unknown presence and value
 */
function unknownContextKeyKnowledge(): DiscoveryContextKeyKnowledge {
  return {
    contextKeyPresence: 'unknown',
    contextKeyValue: 'unknown'
  }
}

/**
 * Checks whether an Allow condition should be reported because Discovery does
 * not authoritatively know whether the key is present.
 *
 * Some matching conditions are still real presence requirements when key
 * presence is unknown. `Null` directly requires presence or absence. `IfExists`
 * and bare negative operators can also match only because a sampled key is
 * missing; those matches require the real request to preserve that absence.
 * `ForAllValues` also always matches a missing key regardless of its base
 * operator, so sampled missing-key matches are presence requirements. `ForAnyValue`
 * missing-key evaluations do not match, so they are reported through the normal
 * non-matching Allow condition path instead.
 *
 * @param conditionAndExplain the evaluated condition and its Discovery knowledge
 * @returns true when a matching Allow condition has an unknown-presence requirement
 */
function allowHasUnknownPresenceRequirement(conditionAndExplain: ConditionAndExplain): boolean {
  if (conditionAndExplain.knowledge.contextKeyPresence !== 'unknown') {
    return false
  }

  const operation = conditionAndExplain.condition.operation()
  if (operation.value().toLowerCase() === 'null') {
    return true
  }

  if (conditionAndExplain.explain.matchedBecauseMissing !== true) {
    return false
  }

  if (operation.isIfExists()) {
    return true
  }

  const baseOperation = baseOperations[operation.baseOperator().toLowerCase()]
  if (operation.setOperator() === 'ForAnyValue') {
    return false
  }
  if (operation.setOperator() === 'ForAllValues') {
    return true
  }

  return !!baseOperation?.isNegative
}

/**
 * Checks whether an Allow condition should be reported because Discovery knows
 * the key is present but not enough value-level facts to trust a placeholder match.
 *
 * When `conditionResult` is already unknown, presence is known, and the key has
 * an applicable value, the uncertainty comes from either the condition key's
 * concrete value or a policy variable referenced by the condition value. In both
 * cases a matching placeholder must still be surfaced as an ignored/output
 * requirement.
 *
 * @param conditionAndExplain the evaluated condition and its Discovery knowledge
 * @returns true when a matched Allow condition still has an unknown value requirement
 */
function allowHasUnknownValueRequirement(conditionAndExplain: ConditionAndExplain): boolean {
  return (
    conditionAndExplain.knowledge.contextKeyPresence === 'known' &&
    conditionAndExplain.knowledge.contextKeyValue !== 'not-applicable'
  )
}

/**
 * Determines the value-knowledge dimension for a condition key.
 *
 * If presence is unknown, the value is also unknown because the key might not be
 * present. If presence is known and the key is absent, the value is not
 * applicable rather than unknown.
 *
 * @param keyExists whether the condition key exists in the request context
 * @param contextKeyPresence whether the condition key's presence is known
 * @param configuredValueIsKnown whether constraints say a present value is authoritative
 * @returns the value-knowledge dimension for the condition key
 */
function contextValueKnowledge(
  keyExists: boolean,
  contextKeyPresence: DiscoveryKnowledgeState,
  configuredValueIsKnown: boolean
): DiscoveryConditionKnowledge['contextKeyValue'] {
  // If the presence is unknown, the value must be unknown by definition
  if (contextKeyPresence === 'unknown') {
    return 'unknown'
  }

  // If the presence is known but the key does not exist, the value doesn't matter
  if (!keyExists) {
    return 'not-applicable'
  }

  // If the presence is known and the key exists, use discovery constraint
  return configuredValueIsKnown ? 'known' : 'unknown'
}

/**
 * Checks whether any policy condition value references an unknown context value.
 *
 * For example, a known `s3:prefix` condition can still be unknown if the policy
 * value is `${aws:SourceAccount}` and `aws:SourceAccount` has unknown value in
 * Discovery mode.
 *
 * @param request the request being evaluated
 * @param condition the condition whose policy values may contain variables
 * @param simulationParameters the simulation mode and Discovery constraints
 * @returns true if any referenced context variable has unknown presence or value
 */
function conditionValuesReferenceUnknownValue(
  request: AwsRequest,
  condition: Condition,
  simulationParameters: SimulationParameters
): boolean {
  for (const value of condition.conditionValues()) {
    for (const variable of contextVariablesInString(value)) {
      const constraint = simulationParameters.discoveryContextKeyConstraints.constraintFor(variable)
      if (!constraint.explicitlyConfigured) {
        continue
      }
      if (!request.contextKeyExists(variable)) {
        if (!constraint.presenceIsKnown) {
          return true
        }
        continue
      }
      if (!constraint.valueIsKnown) {
        return true
      }
    }
  }
  return false
}

/**
 * Extracts context variable names referenced by `${...}` policy variables.
 *
 * Special IAM escapes such as `${*}`, `${?}`, and `${$}` are ignored because
 * they are literal substitutions rather than request context variables.
 *
 * @param value the raw policy value to inspect
 * @returns context variable names referenced by the policy value
 */
function contextVariablesInString(value: string): string[] {
  const variables: string[] = []
  for (const match of value.matchAll(/\$\{(.*?)\}/g)) {
    const variable = match[1]?.split(', ')[0]?.trim()
    if (variable && variable !== '*' && variable !== '?' && variable !== '$') {
      variables.push(variable)
    }
  }
  return variables
}

/**
 * Tests a condition with a null operator
 *
 * @param condition the condition to test
 * @param keyExists whether the key exists in the request
 * @returns the result of evaluating the null operator
 */
function testNull(condition: Condition, keyExists: boolean): ConditionExplain {
  const goalValue = keyExists ? 'false' : 'true'
  const conditionValues: ConditionValueExplain[] = condition.conditionValues().map((value) => {
    return {
      value,
      matches: value.toLowerCase() === goalValue
    }
  })
  const matches = conditionValues.some((value) => value.matches)

  return {
    operator: condition.operation().value(),
    conditionKeyValue: condition.conditionKey(),
    values: condition.valueIsArray() ? conditionValues : conditionValues[0],
    matches,
    matchedBecauseMissing: matches && !keyExists ? true : undefined
  }
}

function singleValueMatch(
  request: AwsRequest,
  condition: Condition,
  baseOperation: BaseConditionOperator,
  keyValue: ContextKey | undefined
): ConditionExplain {
  const isNotOperator = condition.operation().baseOperator().toLowerCase().includes('not')
  if (condition.operation().isIfExists() || isNotOperator) {
    //Check if it exists, return true if it doesn't
    //Double check what happens here if the key is not a valid key or is of the wrong type
    if (!keyValue) {
      const valueExplains: ConditionValueExplain[] = condition.conditionValues().map((value) => ({
        value,
        matches: true
      }))
      return {
        operator: condition.operation().value(),
        conditionKeyValue: condition.conditionKey(),
        values: condition.valueIsArray() ? valueExplains : valueExplains[0],
        matches: true,
        matchedBecauseMissing: true,
        resolvedConditionKeyValue: keyValue
      }
    }
  }

  if (!keyValue || !keyValue.isStringValue()) {
    //Set operator is required for a multi-value key
    //Confirmed this at re:Inforce 2025 IAM431.
    const valueExplains: ConditionValueExplain[] = condition.conditionValues().map((value) => ({
      value,
      matches: false
    }))
    return {
      operator: condition.operation().value(),
      conditionKeyValue: condition.conditionKey(),
      values: condition.valueIsArray() ? valueExplains : valueExplains[0],
      matches: false,
      failedBecauseMissing: !keyValue,
      failedBecauseArray: keyValue?.isArrayValue()
    }
  }

  if (!baseOperation) {
    const valueExplains: ConditionValueExplain[] = condition.conditionValues().map((value) => ({
      value,
      matches: false
    }))

    return {
      operator: condition.operation().value(),
      conditionKeyValue: condition.conditionKey(),
      values: condition.valueIsArray() ? valueExplains : valueExplains[0],
      matches: false,
      missingOperator: true
    }
  }

  const { matches, explains } = baseOperation.matches(
    request,
    keyValue.value,
    condition.conditionValues()
  )

  return {
    matches,
    operator: condition.operation().value(),
    conditionKeyValue: condition.conditionKey(),
    values: condition.valueIsArray() ? explains : explains[0],
    resolvedConditionKeyValue: keyValue.value
  }
}

/**
 * Tests a condition with a ForAllValues set operator
 *
 * @param request the request to test
 * @param condition the condition with ForAllValues set operator
 * @param keyExists whether the key exists in the request
 * @param keyValue the value of the key in the request
 * @param baseOperation the base operation to test the key against
 * @returns the result of evaluating the ForAllValues set operator
 */
function forAllValuesMatch(
  request: AwsRequest,
  condition: Condition,
  keyValue: ContextKey | undefined,
  baseOperation: BaseConditionOperator
): ConditionExplain {
  const matchingValueExplains: ConditionValueExplain[] = condition
    .conditionValues()
    .map((value) => ({
      value,
      matches: true
    }))
  const notMatchingValueExplains: ConditionValueExplain[] = condition
    .conditionValues()
    .map((value) => ({
      value,
      matches: false
    }))

  if (!keyValue) {
    return {
      operator: condition.operation().value(),
      conditionKeyValue: condition.conditionKey(),
      values: matchingValueExplains,
      matches: true,
      matchedBecauseMissing: true
    }
  }

  // If the key only has a single value, convert it to an array to process
  if (keyValue.isStringValue()) {
    keyValue = new ContextKeyImpl(keyValue.name, [keyValue.value])
  }

  if (!keyValue.isArrayValue()) {
    throw new Error('Key value is not an array, this is a bug.')
  }

  if (!baseOperation) {
    return {
      operator: condition.operation().value(),
      conditionKeyValue: condition.conditionKey(),
      values: notMatchingValueExplains,
      matches: false,
      missingOperator: true
    }
  }

  const valueExplains = keyValue.values.map((value) => {
    const { matches, explains } = baseOperation.matches(request, value, condition.conditionValues())
    return {
      requestValue: value,
      matches,
      explains
    }
  })

  const anyNonMatches = valueExplains.some((valueExplain) => !valueExplain.matches)
  const overallMatch = !anyNonMatches
  const unmatchedValues: string[] = []

  const explains: Record<string, ConditionValueExplain> = {}
  for (const valueExplain of valueExplains) {
    if (!baseOperation.isNegative && !valueExplain.matches) {
      unmatchedValues.push(valueExplain.requestValue)
    } else if (baseOperation.isNegative && valueExplain.matches) {
      unmatchedValues.push(valueExplain.requestValue)
    }
    for (const explain of valueExplain.explains) {
      let theExplain = explains[explain.value]
      if (!theExplain) {
        explains[explain.value] = {
          value: explain.value,
          matches: overallMatch
        }
        theExplain = explains[explain.value]
      }
      if (explain.matches && !baseOperation.isNegative) {
        theExplain.matchingValues = theExplain.matchingValues || []
        theExplain.matchingValues.push(valueExplain.requestValue)
      } else if (!explain.matches && baseOperation.isNegative) {
        theExplain.negativeMatchingValues = theExplain.negativeMatchingValues || []
        theExplain.negativeMatchingValues.push(valueExplain.requestValue)
      }
    }
  }

  return {
    operator: condition.operation().value(),
    conditionKeyValue: condition.conditionKey(),
    values: Object.values(explains),
    matches: overallMatch,
    unmatchedValues
  }
}

/**
 * Test a condition with a ForAnyValue set operator
 *
 * @param request the request to test
 * @param condition the condition with ForAnyValue set operator
 * @param keyExists whether the key exists in the request
 * @param keyValue the value of the key in the request
 * @param baseOperation the base operation to test the key against
 * @returns the result of evaluating the ForAnyValue set operator
 */
function forAnyValueMatch(
  request: AwsRequest,
  condition: Condition,
  keyValue: ContextKey | undefined,
  baseOperation: BaseConditionOperator
): ConditionExplain {
  const failedValueExplains: ConditionValueExplain[] = condition.conditionValues().map(
    (value) =>
      ({
        value,
        matches: false
      }) as ConditionValueExplain
  )

  if (!keyValue) {
    return {
      operator: condition.operation().value(),
      conditionKeyValue: condition.conditionKey(),
      values: failedValueExplains,
      matches: false,
      failedBecauseMissing: true
    }
    // return 'NoMatch'
  }

  // If the key only has a single value, convert it to an array to process
  if (keyValue.isStringValue()) {
    keyValue = new ContextKeyImpl(keyValue.name, [keyValue.value])
  }

  if (!keyValue.isArrayValue()) {
    throw new Error('Key value is not an array, this is a bug.')
  }

  if (!baseOperation) {
    return {
      operator: condition.operation().value(),
      conditionKeyValue: condition.conditionKey(),
      values: failedValueExplains,
      matches: false,
      missingOperator: true
    }
  }

  const valueExplains = keyValue.values.map((value) => {
    const { matches, explains } = baseOperation.matches(request, value, condition.conditionValues())
    return {
      requestValue: value,
      matches,
      explains
    }
  })

  const overallMatch = valueExplains.some((valueExplain) => valueExplain.matches)
  const unmatchedValues: string[] = []

  const explains: Record<string, ConditionValueExplain> = {}
  for (const valueExplain of valueExplains) {
    if (!baseOperation.isNegative && !valueExplain.matches) {
      unmatchedValues.push(valueExplain.requestValue)
    } else if (baseOperation.isNegative && valueExplain.matches) {
      unmatchedValues.push(valueExplain.requestValue)
    }
    for (const explain of valueExplain.explains) {
      let theExplain = explains[explain.value]
      if (!theExplain) {
        explains[explain.value] = {
          value: explain.value,
          matches: overallMatch
        }
        theExplain = explains[explain.value]
      }
      if (explain.matches) {
        theExplain.matchingValues = theExplain.matchingValues || []
        theExplain.matchingValues.push(valueExplain.requestValue)
      }
    }
  }

  return {
    operator: condition.operation().value(),
    conditionKeyValue: condition.conditionKey(),
    values: Object.values(explains),
    matches: overallMatch,
    unmatchedValues
  }
}
