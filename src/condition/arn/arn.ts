import { splitArnParts } from '@actsecurity/iam-utils'
import { type ConditionValueExplain } from '../../explain/statementExplain.js'
import { type AwsRequest } from '../../request/request.js'
import { convertIamString, isNotDefined } from '../../util.js'

/**
 * Checks to see if a single ARN matches in ArnLike format
 *
 * @param policyArn the ARN to check against
 * @param requestArn the ARN to check
 * @param request the request to check
 * @returns if the ARN matches
 */
export function arnMatches(
  policyArn: string,
  requestArn: string,
  request: AwsRequest,
  expectMatch: boolean
): ConditionValueExplain {
  const policyParts = splitArnParts(policyArn)
  const requestParts = splitArnParts(requestArn)
  // If any of the parts are missing, return false
  if (
    isNotDefined(policyParts.partition) ||
    isNotDefined(policyParts.service) ||
    isNotDefined(policyParts.region) ||
    isNotDefined(policyParts.accountId) ||
    isNotDefined(policyParts.resource)
  ) {
    return {
      matches: false,
      value: policyArn,
      errors: ['Invalid ARN']
    }
  }

  const resolvedPolicyArn = [
    'arn',
    policyParts.partition,
    policyParts.service,
    policyParts.region,
    policyParts.accountId,
    policyParts.resource
  ]
    .map((part) =>
      convertIamString(part, request, { convertToRegex: false, replaceWildcards: false })
    )
    .join(':')

  const resolvedValue = resolvedPolicyArn == policyArn ? undefined : resolvedPolicyArn

  // If any of the parts are missing, return false
  if (
    isNotDefined(requestParts.partition) ||
    isNotDefined(requestParts.service) ||
    isNotDefined(requestParts.region) ||
    isNotDefined(requestParts.accountId) ||
    isNotDefined(requestParts.resource)
  ) {
    return {
      matches: false,
      value: policyArn,
      resolvedValue,
      errors: [`request ARN '${requestArn}' is not a valid ARN`]
    }
  }

  const allErrors: string[] = []
  const replaceAndMatch = (policyPart: string, requestPart: string): boolean => {
    const { pattern, errors } = convertIamString(policyPart, request, { replaceWildcards: true })
    allErrors.push(...(errors || []))
    return pattern.test(requestPart)
  }

  const matches =
    replaceAndMatch(policyParts.partition, requestParts.partition) &&
    replaceAndMatch(policyParts.service, requestParts.service) &&
    replaceAndMatch(policyParts.region, requestParts.region) &&
    replaceAndMatch(policyParts.accountId, requestParts.accountId) &&
    replaceAndMatch(policyParts.resource, requestParts.resource)

  return {
    matches: matches == expectMatch && allErrors.length == 0,
    value: policyArn,
    resolvedValue,
    errors: allErrors.length > 0 ? allErrors : undefined
  }
}
