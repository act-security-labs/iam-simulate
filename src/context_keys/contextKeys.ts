import { type ConditionKey, findConditionKey } from '@actsecurity/iam-data'
import { getGlobalConditionKeyWithOrWithoutPrefix } from '../global_conditions/globalConditionKeys.js'
import { type ConditionKeyType } from './contextKeyTypes.js'

const oidcKeys = new Set([
  'amr',
  'aud',
  'email',
  'oaud',
  'sub',
  'actor',
  'actor_id',
  'job_workflow_ref',
  'repository',
  'repository_id',
  'workflow',
  'ref',
  'environment',
  'enterprise_id',
  'app_id',
  'user_id',
  'id',
  'project_id',
  'rpst_id',
  'google/organization_number'
])
const oidcProviderPattern = /^[0-9a-zA-Z\._\-]+$/

/**
 * Check if a context key actually exists
 *
 * @param key The context key to check
 * @returns true if the context key is valid, false otherwise
 */
export async function isActualContextKey(key: string): Promise<boolean> {
  if (isOidcConditionKey(key)) {
    return true
  }

  const dataKey = await findConditionKey(key)
  return !!dataKey
}

/**
 * Takes context key and returns the details for it, accounting for any variables in the key
 *
 * @param contextKey The context key to get the details for
 * @returns The details for the context key if it exists. if the key has variables in it it will return the details for the variable key
 */
async function serviceContextKeyDetails(contextKey: string): Promise<ConditionKey | undefined> {
  return findConditionKey(contextKey)
}

/**
 * Check the capitalization of a context key and return the correct capitalization
 *
 * @param contextKey the condition key to check
 * @returns if the condition key is an array type
 */
export async function normalizeContextKeyCase(contextKey: string): Promise<string> {
  const serviceKey = await serviceContextKeyDetails(contextKey)
  if (serviceKey) {
    return replaceVariableInContextKey(serviceKey.key, contextKey)
  }

  const globalConditionKey = getGlobalConditionKeyWithOrWithoutPrefix(contextKey)
  if (globalConditionKey) {
    return replaceVariableInContextKey(globalConditionKey.key, contextKey)
  }

  if (isOidcConditionKey(contextKey)) {
    return contextKey
  }

  throw new Error(`Context key ${contextKey} not found`)
}

/**
 * Replaces a variable in a context key with the actual value from a policy
 *
 * @param specKey the string value of the condition key spec
 * @param actualKey the string value of the condition key in the policy
 * @returns the spec condition key with the variable portion replaced with the actual value
 */
function replaceVariableInContextKey(specKey: string, actualKey: string): string {
  const slashIndex = specKey.indexOf('/')
  if (slashIndex === -1) {
    return specKey
  }
  const prefix = specKey.slice(0, slashIndex)
  const suffix = actualKey.slice(slashIndex)
  return prefix + suffix
}

/**
 * Get the type of a context key
 *
 * @param contextKey - The string condition key to get the type for
 * @returns The type of the condition key
 * @throws an error if the condition key is not found
 */
export async function typeForContextKey(contextKey: string): Promise<ConditionKeyType> {
  const globalConditionKey = getGlobalConditionKeyWithOrWithoutPrefix(contextKey)
  if (globalConditionKey) {
    return globalConditionKey.type as ConditionKeyType
  }

  const keyDetails = await serviceContextKeyDetails(contextKey)
  if (keyDetails) {
    return keyDetails.type as ConditionKeyType
  }

  throw new Error(`Condition key ${contextKey} not found`)
}

/**
 * Checks if a string is a valid OIDC condition key
 *
 * @param key the key to check
 * @returns true if the key is a valid OIDC condition key
 */
function isOidcConditionKey(key: string): boolean {
  const parts = key.split(':')
  if (parts.length !== 2) {
    return false
  }
  const [service, action] = parts
  return oidcKeys.has(action) && oidcProviderPattern.test(service)
}
