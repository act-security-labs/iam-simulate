import { type Policy } from '@actsecurity/iam-policy'
import { getVariablesFromString } from '../util.js'
import { isActualContextKey, normalizeContextKeyCase } from './contextKeys.js'

/**
 * Find all the context keys in a list of policies
 *
 * @param policies - The list of policies to search
 * @returns The list of valid and invalid context keys found in the policies
 */
export async function findContextKeys(
  policies: Policy[]
): Promise<{ validKeys: string[]; invalidKeys: string[] }> {
  const rawKeys = new Set<string>()
  for (const policy of policies) {
    getContextKeysFromPolicy(policy).forEach((v) => rawKeys.add(v))
  }
  const validKeys = new Set<string>()
  const invalidKeys = new Set<string>()
  for (const key of rawKeys) {
    const valid = await isActualContextKey(key)
    if (valid) {
      const normalizedKey = await normalizeContextKeyCase(key)
      validKeys.add(normalizedKey)
    } else {
      invalidKeys.add(key)
    }
  }

  return {
    validKeys: Array.from(validKeys),
    invalidKeys: Array.from(invalidKeys)
  }
}

/**
 * Get the context variables used in a policy
 *
 * @param policy - The policy to extract variables from
 * @returns The list of variables used in the policy
 */
export function getContextKeysFromPolicy(policy: Policy): string[] {
  const variables: string[] = []
  for (const statement of policy.statements()) {
    if (statement.isResourceStatement()) {
      statement.resources().forEach((r) => {
        variables.push(...getVariablesFromString(r.value()))
      })
      for (const condition of statement.conditions()) {
        variables.push(condition.conditionKey())
        condition.conditionValues().forEach((v) => {
          variables.push(...getVariablesFromString(v))
        })
      }
    }
  }

  return variables
}
