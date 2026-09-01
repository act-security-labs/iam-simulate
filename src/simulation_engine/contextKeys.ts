import {
  getAllGlobalConditionKeys,
  iamActionDetails,
  type ResourceType
} from '@actsecurity/iam-data'
import { isS3BucketOrObjectArn, isWildcardOnlyAction, lowerCaseAll } from '../util.js'
import { getResourceTypesForAction } from './resourceTypes.js'

/**
 * Get the allowed context keys for a request.
 *
 * @param service The service the action belongs to
 * @param action The action to get the allowed context keys for
 * @param resource The resource the action is being performed on
 * @param bucketAbacEnabled Whether ABAC is enabled on the S3 bucket (only applies to S3)
 * @returns The allowed context keys for the request as lower case strings
 * @throws error if the service or action does not exist
 */
export async function allowedContextKeysForRequest(
  service: string,
  action: string,
  resource: string,
  bucketAbacEnabled: boolean,
  suggestedResourceType: ResourceType | undefined
): Promise<string[]> {
  const actionDetails = await iamActionDetails(service, action)
  const actionConditionKeys = lowerCaseAll(actionDetails.conditionKeys)

  const isWildCardOnly = await isWildcardOnlyAction(service, action)
  if (isWildCardOnly) {
    return [...actionConditionKeys, ...lowerCaseGlobalConditionKeys()]
  }

  let resourceType = suggestedResourceType
  if (!resourceType) {
    const resourceTypes = await getResourceTypesForAction(service, action, resource)
    if (resourceTypes.length === 0) {
      throw new Error(`No resource types found for action ${action} on service ${service}`)
    } else if (resourceTypes.length > 1) {
      throw new Error(`Multiple resource types found for action ${action} on service ${service}`)
    }
    resourceType = resourceTypes[0]
  }

  const resourceTypeConditions = [
    ...(resourceType.conditionKeys ?? []),
    ...(actionDetails.resourceTypes.find((rt) => rt.name === resourceType!.key)?.conditionKeys ??
      [])
  ]

  const allKeys = [
    ...lowerCaseAll(resourceTypeConditions),
    ...actionConditionKeys,
    ...lowerCaseGlobalConditionKeys()
  ]

  if (!isS3BucketOrObjectArn(resource) || bucketAbacEnabled) {
    return allKeys
  }

  // Filter out S3 ABAC keys if bucket ABAC is not enabled
  return allKeys.filter(
    (key) => !key.startsWith('aws:resourcetag/') && !key.startsWith('s3:buckettag/')
  )
}

let lowerCaseConditionKeys: string[] | undefined
function lowerCaseGlobalConditionKeys(): string[] {
  if (!lowerCaseConditionKeys) {
    lowerCaseConditionKeys = getAllGlobalConditionKeys().map((k) => k.toLowerCase())
  }
  return lowerCaseConditionKeys
}
