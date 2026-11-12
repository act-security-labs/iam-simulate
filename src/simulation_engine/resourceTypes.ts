import { iamActionDetails, iamResourceTypeDetails, type ResourceType } from '@actsecurity/iam-data'
import { mostSpecificMatchingResourceTypePatterns } from '@actsecurity/iam-utils'

const qualifiedLambdaFunctionArnPattern = /^arn:[^:]+:lambda:[^:]+:[^:]+:function:[^:]+:([^:]+)$/i
const numericQualifierPattern = /^\d+$/

/**
 * Get the the possible resource types for an action and resource
 *
 * @param service the service the action belongs to
 * @param action the action to get the resource type for
 * @param resource the resource type matching the action, if any
 * @throws an error if the service or action does not exist, or if the action is a wildcard only action
 */
export async function getResourceTypesForAction(
  service: string,
  action: string,
  resource: string
): Promise<ResourceType[]> {
  const actionDetails = await iamActionDetails(service, action)
  if (actionDetails.resourceTypes.length === 0) {
    throw new Error(`${service}:${action} does not have any resource types`)
  }

  const actionResourceTypes: ResourceType[] = []
  for (const rt of actionDetails.resourceTypes) {
    actionResourceTypes.push(await iamResourceTypeDetails(service, rt.name))
  }

  const matchingPatterns = mostSpecificMatchingResourceTypePatterns(
    resource,
    actionResourceTypes.map((resourceType) => resourceType.arn)
  )

  const matchingTypes = actionResourceTypes.filter((resourceType) =>
    matchingPatterns.includes(resourceType.arn)
  )
  return disambiguateLambdaQualifier(service, resource, matchingTypes)
}

/**
 * Select the Lambda version or alias for a concrete qualified function ARN.
 * Patterns retain all matching types so each can be evaluated independently.
 *
 * @param service IAM service name
 * @param resource requested resource ARN or pattern
 * @param matchingTypes resource types matched by the action and ARN
 * @returns the matching types, narrowed only for a concrete Lambda qualifier
 */
function disambiguateLambdaQualifier(
  service: string,
  resource: string,
  matchingTypes: ResourceType[]
): ResourceType[] {
  if (matchingTypes.length !== 2 || service.toLowerCase() !== 'lambda' || resource.includes('*')) {
    return matchingTypes
  }
  const match = qualifiedLambdaFunctionArnPattern.exec(resource)
  if (
    !match ||
    !matchingTypes.some((type) => type.key === 'function alias') ||
    !matchingTypes.some((type) => type.key === 'function version')
  ) {
    return matchingTypes
  }
  const selected = numericQualifierPattern.test(match[1]) ? 'function version' : 'function alias'
  return matchingTypes.filter((type) =>
    type.key !== 'function alias' && type.key !== 'function version' ? true : type.key === selected
  )
}
