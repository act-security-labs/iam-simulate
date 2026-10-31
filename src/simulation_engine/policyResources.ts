import { type ResourceType } from '@actsecurity/iam-data'
import { type Statement } from '@actsecurity/iam-policy'
import {
  actionMatchesPattern,
  resourceArnWithWildcardsToRegex,
  resourceStringMatchesResourceTypePattern
} from '@actsecurity/iam-utils'
import { type PolicyWithName } from '../core_engine/CoreSimulatorEngine.js'
import { expandShortArn, resourceArnsOverlap } from '../util/resourceStrings.js'

/**
 * Extracts matching resource strings from a set of policies for a given action and resource pattern.
 *
 * @param policies Array of policies to search through (undefined entries are skipped)
 * @param action The action to match against policy statements
 * @param resourceType The resource type to filter resource strings by
 * @param resourceArnPattern The resource ARN pattern to match against
 * @param shouldExpandShortArns Whether to expand short ARNs (fewer than 6 segments) by padding with wildcards
 * @param effect Statement effect to extract, defaulting to allow
 * @returns Array of unique resource strings that match the criteria
 */
export function getMatchingResourceStringsForPolicies(
  policies: (PolicyWithName | undefined)[],
  action: string,
  resourceType: ResourceType,
  resourceArnPattern: string,
  shouldExpandShortArns: boolean,
  effect: 'allow' | 'deny' = 'allow'
): string[] {
  const resourceStrings = new Set<string>()
  for (const policy of policies) {
    if (!policy) {
      continue
    }
    for (const statement of policy.statements()) {
      const stmtResourceStrings = getResourceStringsFromStatement(
        statement,
        action,
        resourceType,
        resourceArnPattern,
        shouldExpandShortArns,
        effect
      )
      for (const rs of stmtResourceStrings) {
        resourceStrings.add(rs)
      }
    }
  }
  return Array.from(resourceStrings)
}

/**
 * Extracts resource strings from a policy statement with the requested effect on the action.
 *
 * @param statement The policy statement to analyze
 * @param action The action to match against the statement
 * @param resourceType The resource type to filter by
 * @param resourceArnPattern The resource ARN pattern to match
 * @param shouldExpandShortArns Whether to expand short ARNs (fewer than 6 segments) by padding with wildcards
 * @param effect Statement effect to extract, defaulting to allow
 * @returns Array of resource strings, or empty array if the statement does not match the action and effect
 */
export function getResourceStringsFromStatement(
  statement: Statement,
  action: string,
  resourceType: ResourceType,
  resourceArnPattern: string,
  shouldExpandShortArns: boolean,
  effect: 'allow' | 'deny' = 'allow'
): string[] {
  const actionMatches =
    effect === 'allow'
      ? statementAllowsAction(statement, action)
      : statementDeniesAction(statement, action)
  if (actionMatches) {
    return statementResourceStringsForResourceTypeAndPattern(
      statement,
      resourceType,
      resourceArnPattern,
      shouldExpandShortArns,
      effect
    )
  }
  return []
}

/**
 * Extracts resource strings from a statement's Resource or NotResource elements that match the given criteria.
 *
 * @param statement The policy statement to analyze
 * @param resourceType The resource type to filter by
 * @param resourceArnPattern The resource ARN pattern to check for overlap
 * @param shouldExpandShortArns Whether to expand short ARNs (fewer than 6 segments) by padding with wildcards
 * @param effect Statement effect to extract, defaulting to allow
 * @returns Array of matching resource strings, or ['*'] for certain NotResource cases
 */
export function statementResourceStringsForResourceTypeAndPattern(
  statement: Statement,
  resourceType: ResourceType,
  resourceArnPattern: string,
  shouldExpandShortArns: boolean,
  effect: 'allow' | 'deny' = 'allow'
): string[] {
  const hasRequestedEffect = effect === 'allow' ? statement.isAllow() : statement.isDeny()
  if (statement.isResourceStatement() && hasRequestedEffect) {
    const resourceStrings: string[] = []
    for (const stmtResource of statement.resources()) {
      const effectiveValue = shouldExpandShortArns
        ? expandShortArn(stmtResource.value())
        : stmtResource.value()
      if (resourceStringMatchesResourceTypePattern(effectiveValue, resourceType.arn)) {
        if (resourceArnsOverlap(resourceArnPattern, effectiveValue)) {
          resourceStrings.push(stmtResource.value())
        }
      }
    }
    return resourceStrings
  }

  if (statement.isNotResourceStatement() && hasRequestedEffect) {
    for (const stmtNotResource of statement.notResources()) {
      const effectiveValue = shouldExpandShortArns
        ? expandShortArn(stmtNotResource.value())
        : stmtNotResource.value()
      // If any NotResource string equals or is a superset of the resource type pattern, then the statement does not apply to the string. Otherwise, it should return the string '*'
      if (
        effectiveValue === resourceArnPattern ||
        isResourceArnSuperset(effectiveValue, resourceArnPattern)
      ) {
        return []
      }
    }
    return ['*']
  }

  // If it's a statement that has no Resource or NotResource such as a trust policy, just return the original pattern
  return [resourceArnPattern]
}

/**
 * Determines if a policy statement allows the specified action.
 *
 * @param statement The policy statement to check
 * @param action The action to test against the statement
 * @returns true if the statement allows the action, false otherwise
 */
export function statementAllowsAction(statement: Statement, action: string): boolean {
  if (statement.isActionStatement() && statement.isAllow()) {
    for (const stmtAction of statement.actions()) {
      if (actionMatchesPattern(action, stmtAction.value())) {
        return true
      }
    }
    return false
  } else if (statement.isNotActionStatement() && statement.isAllow()) {
    for (const stmtAction of statement.notActions()) {
      if (actionMatchesPattern(action, stmtAction.value())) {
        return false
      }
    }
    return true
  }

  return false
}

/**
 * Determines if an explicit deny statement applies to an action.
 *
 * @param statement The policy statement to check
 * @param action The action to test against the statement
 * @returns true when the deny statement applies to the action
 */
function statementDeniesAction(statement: Statement, action: string): boolean {
  if (statement.isActionStatement() && statement.isDeny()) {
    return statement
      .actions()
      .some((statementAction) => actionMatchesPattern(action, statementAction.value()))
  }
  if (statement.isNotActionStatement() && statement.isDeny()) {
    return !statement
      .notActions()
      .some((statementAction) => actionMatchesPattern(action, statementAction.value()))
  }
  return false
}

function isResourceArnSuperset(arnSuperset: string, arnSubset: string): boolean {
  const regexSuperset = resourceArnWithWildcardsToRegex(arnSuperset)
  return regexSuperset.test(arnSubset)
}
