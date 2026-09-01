import { type Resource, type Statement } from '@actsecurity/iam-policy'
import {
  type ResourceExplain,
  resourceMismatchReasons,
  type StatementExplain
} from '../explain/statementExplain.js'
import { type PolicyType } from '../policyType.js'
import { type AwsRequest } from '../request/request.js'
import { convertIamString, getResourceSegments } from '../util.js'

type ShortArnBehavior = 'expand' | 'reject' | 'noMatch'

/**
 * Settings that control how short ARNs (fewer than 6 colon-separated segments) are handled
 * for a given policy type during resource matching.
 */
interface PolicyTypeResourceSettings {
  /** Behavior for short ARNs without any wildcard characters. */
  shortArnWithoutWildcard: ShortArnBehavior
  /** Behavior for short ARNs with wildcard characters. */
  shortArnWithWildcard: ShortArnBehavior
}

/**
 * Map of resource matching settings per policy type. Controls how short ARNs are treated:
 * - `'expand'` — treat missing trailing segments as `*`, then match normally
 * - `'reject'` — return an error (ARN is not valid for this policy type)
 * - `'noMatch'` — silently does not match
 */
const policyTypeResourceSettings: Record<PolicyType, PolicyTypeResourceSettings> = {
  identity: { shortArnWithoutWildcard: 'expand', shortArnWithWildcard: 'expand' },
  session: { shortArnWithoutWildcard: 'expand', shortArnWithWildcard: 'expand' },
  pb: { shortArnWithoutWildcard: 'expand', shortArnWithWildcard: 'expand' },
  resource: { shortArnWithoutWildcard: 'noMatch', shortArnWithWildcard: 'expand' },
  vpce: { shortArnWithoutWildcard: 'noMatch', shortArnWithWildcard: 'expand' },
  scp: { shortArnWithoutWildcard: 'reject', shortArnWithWildcard: 'expand' },
  rcp: { shortArnWithoutWildcard: 'reject', shortArnWithWildcard: 'reject' }
}

/**
 * Create a lightweight Resource object from an expanded ARN string.
 * Used when a short ARN is padded with `*` segments to form a full 6-segment ARN.
 *
 * @param expandedValue the full 6-segment ARN string
 * @returns a Resource object that can be used in the existing matching logic
 */
function createExpandedResource(expandedValue: string): Resource {
  const parts = expandedValue.split(':')
  const resource = {
    value: () => expandedValue,
    isAllResources: () => false,
    isArnResource: () => true,
    path: () => '',
    partition: () => parts[1],
    service: () => parts[2],
    region: () => parts[3],
    account: () => parts[4],
    resource: () => parts.slice(5).join(':')
  }
  return resource as unknown as Resource
}

/**
 * Convert a resource segment to a regular expression. This is without variables.
 *
 * @param segment the segment to convert to a regular expression
 * @returns a regular that replaces any wildcards in the segment with the appropriate regular expression.
 */
function convertResourceSegmentToRegex(segment: string): RegExp {
  if (segment.indexOf(':') != -1) {
    throw new Error('Segment should not contain a colon')
  }
  const pattern = '^' + segment.replace(/\?/g, '.').replace(/\*/g, '.*?') + '$'
  return new RegExp(pattern, 'i')
}

/**
 * Replace regex characters in a resource pattern with escaped versions.
 *
 * @param pattern the resource pattern to escape for use inside a regular expression
 * @returns the pattern with regex metacharacters escaped
 */
function escapeResourcePatternRegexCharacters(pattern: string): string {
  return pattern.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

/**
 * Convert a request resource pattern to a regex string for overlap checks.
 * Request resources support asterisks as wildcards, but question marks are literals.
 *
 * @param requestString the request resource pattern to convert
 * @returns a regex string that matches the request resource pattern
 */
function requestResourcePatternToRegexString(requestString: string): string {
  return '^' + escapeResourcePatternRegexCharacters(requestString).replace(/\\\*/g, '.*?') + '$'
}

/**
 * Convert a policy resource pattern to a regex string for overlap checks.
 * Policy resources support asterisks and question marks as IAM wildcards.
 *
 * @param policyString the policy resource pattern to convert
 * @returns a regex string that matches the policy resource pattern
 */
function policyResourcePatternToRegexString(policyString: string): string {
  return (
    '^' +
    escapeResourcePatternRegexCharacters(policyString)
      .replace(/\\\?/g, '.')
      .replace(/\\\*/g, '.*?') +
    '$'
  )
}

/**
 * Check if a request matches the Resource or NotResource elements of a statement.
 *
 * @param request the request to check
 * @param statement the statement to check against
 * @param policyType the type of policy being evaluated
 * @returns true if the request matches the resources in the statement, false otherwise
 */
export function requestMatchesStatementResources(
  request: AwsRequest,
  statement: Statement,
  policyType: PolicyType
): { matches: boolean; details: Pick<StatementExplain, 'resources' | 'notResources'> } {
  if (statement.isResourceStatement()) {
    const { matches, explains } = requestMatchesResources(
      request,
      statement.resources(),
      'Resource',
      statement.effect() as 'Allow' | 'Deny',
      policyType
    )
    if (!statement.resourceIsArray()) {
      return { matches, details: { resources: explains[0] } }
    }
    return { matches, details: { resources: explains } }
  } else if (statement.isNotResourceStatement()) {
    const { matches, explains } = requestMatchesNotResources(
      request,
      statement.notResources(),
      'NotResource',
      statement.effect() as 'Allow' | 'Deny',
      policyType
    )
    if (!statement.notResourceIsArray()) {
      return { matches, details: { notResources: explains[0] } }
    }
    return { matches, details: { notResources: explains } }
  }
  return { matches: true, details: {} }
}

/**
 * Check if a request matches a set of resources.
 *
 * @param request the request to check
 * @param policyResources the resources to check against
 * @param resourceType whether this is a Resource or NotResource element
 * @param effect the effect of the statement
 * @param policyType the type of policy being evaluated
 * @returns true if the request matches any of the resources, false otherwise
 */
export function requestMatchesResources(
  request: AwsRequest,
  policyResources: Resource[],
  resourceType: 'Resource' | 'NotResource',
  effect: 'Allow' | 'Deny',
  policyType: PolicyType
): { matches: boolean; explains: ResourceExplain[] } {
  const explains = policyResources.map((policyResource) =>
    singleResourceMatchesRequest(request, policyResource, resourceType, effect, policyType)
  )
  const matches = explains.some((explain) => explain.matches)
  return { matches, explains }
}

/**
 * Check if a request matches a NotResource element in a policy.
 *
 * @param request the request to check
 * @param policyResources the resources to check against
 * @param resourceType whether this is a Resource or NotResource element
 * @param effect the effect of the statement
 * @param policyType the type of policy being evaluated
 * @returns true if the request does not match any of the resources, false otherwise
 */
export function requestMatchesNotResources(
  request: AwsRequest,
  policyResources: Resource[],
  resourceType: 'Resource' | 'NotResource',
  effect: 'Allow' | 'Deny',
  policyType: PolicyType
): { matches: boolean; explains: ResourceExplain[] } {
  const explains = policyResources.map((policyResource) => {
    const explain = singleResourceMatchesRequest(
      request,
      policyResource,
      resourceType,
      effect,
      policyType
    )
    if (shouldInvertNotResourceExplain(explain)) {
      explain.matches = !explain.matches
      delete explain.errors
      delete explain.mismatchReason
    }
    return explain
  })
  const matches = !explains.some((explain) => !explain.matches)
  return { matches, explains }
}

/**
 * Determine whether a Resource match explain can be inverted for NotResource matching.
 *
 * The resource mismatch reason registry owns the decision about which mismatches
 * definitively prove the request is outside the NotResource set and can be inverted.
 *
 * @param explain the Resource matching explain to inspect
 * @returns true when the explain should be inverted for NotResource semantics
 */
function shouldInvertNotResourceExplain(explain: ResourceExplain): boolean {
  if (explain.matches) {
    return true
  }

  if (!explain.mismatchReason) {
    throw new Error(`Non-matching resource explain is missing mismatchReason: ${explain.resource}`)
  }

  return resourceMismatchReasons[explain.mismatchReason].invertible
}

/*
Specifications for **request resource** wildcards:
- Asterisks (*) can be used to match any sequence of characters (including an empty sequence)
- Asterisks can appear in any segment of the ARN (partition, service, region, account, resource)
- Asterisks are not greedy, and can be followed or preceded by other characters in the same segment
- Existing rules of matching wildcard segments in ARNs still apply
- Question marks (?) are not supported in the request resource ARN

If the string in the policy is the same as the resolved string after variable substitution, it is a match

For an Allow/Resource Statement:
- If the resolved string matches the request resource, it is a match
- If the resolved string is a superset of the request resource, it is a match
- If the resolved string is a subset of the request resource, it is a match
- If there is no overlap at all between the resolved string and the request resource, it is not a match

For a Deny/Resource Statement:
- If the resolved string matches the request resource, it is a match
- If the resolved string is a superset of the request resource, it is a match
- If the resolved string is a subset of the request resource, it is not a match
- If there is no overlap at all between the resolved string and the request resource, it is not a match

For an Allow/NotResource Statement:
- If the resolved string matches the request resource, it is not a match
- If the resolved string is a superset of the request resource, it is not a match
- If the resolved string is a subset of the request resource, it is a match
- If there is no overlap at all between the resolved string and the request resource, it is a match

For a Deny/NotResource Statement:
- If the resolved string matches the request resource, it is not a match
- If the resolved string is a superset of the request resource, it is not a match
- If the resolved string is a subset of the request resource, it is not a match
- If there is no overlap at all between the resolved string and the request resource, it is a match
*/

/**
 * Check if a single resource matches a request.
 *
 * @param request the request to check against
 * @param policyResource the resource to check against
 * @param resourceType whether this is a Resource or NotResource element
 * @param effect the effect of the statement
 * @param policyType the type of policy being evaluated
 * @returns true if the request matches the resource, false otherwise
 */
function singleResourceMatchesRequest(
  request: AwsRequest,
  policyResource: Resource,
  resourceType: 'Resource' | 'NotResource',
  effect: 'Allow' | 'Deny',
  policyType: PolicyType
): ResourceExplain {
  // Policy is all resources
  if (policyResource.isAllResources()) {
    return {
      resource: policyResource.value(),
      matches: true
    }
  }

  // Short ARN handling — fewer than 6 colon-separated segments
  if (policyResource.isArnResource() && policyResource.value().split(':').length < 6) {
    const settings = policyTypeResourceSettings[policyType]
    // For policy types that reject short ARNs without wildcards, only a wildcard
    // in the last segment counts — a wildcard in the middle doesn't make it valid.
    const lastSegment = policyResource.value().split(':').at(-1) ?? ''
    const hasTrailingWildcard = lastSegment.endsWith('*')
    const hasAnyWildcard = policyResource.value().includes('*')
    const hasWildcard =
      settings.shortArnWithoutWildcard === 'reject' ? hasTrailingWildcard : hasAnyWildcard
    const behavior = hasWildcard ? settings.shortArnWithWildcard : settings.shortArnWithoutWildcard

    if (behavior === 'reject') {
      return {
        resource: policyResource.value(),
        matches: false,
        errors: ['Policy resource ARN is not valid for this policy type'],
        mismatchReason: 'invalidPolicyResourceArn'
      }
    }

    if (behavior === 'noMatch') {
      return {
        resource: policyResource.value(),
        matches: false,
        mismatchReason: 'shortArnNoMatch'
      }
    }

    // behavior === 'expand': pad missing segments with '*' and recurse with expanded resource
    const segments = policyResource.value().split(':')
    while (segments.length < 6) {
      segments.push('*')
    }
    const result = singleResourceMatchesRequest(
      request,
      createExpandedResource(segments.join(':')),
      resourceType,
      effect,
      policyType
    )
    // Preserve the original (unexpanded) resource value in the explain
    result.resource = policyResource.value()
    if (!result.matches && result.mismatchReason) {
      result.mismatchReason = 'shortArnExpandedMismatch'
    }
    return result
  }

  // Request is all resources
  if (request.resource?.isAllResources()) {
    // For wildcard-only actions, only a literal "*" policy resource (handled above) grants access.
    // A specific ARN in the policy does not match a wildcard-only action's "*" request resource.
    if (request.wildcardOnlyAction) {
      return {
        resource: policyResource.value(),
        matches: false,
        mismatchReason: 'wildcardOnlyActionSpecificResource'
      }
    }

    if (effect === 'Allow' && resourceType === 'Resource') {
      return {
        resource: policyResource.value(),
        matches: true
      }
    } else if (effect === 'Allow' && resourceType === 'NotResource') {
      return {
        resource: policyResource.value(),
        matches: false, // This gets inverted in the caller
        mismatchReason: 'requestAllResourcesSpecificNotResource'
      }
    } else if (effect === 'Deny' && resourceType === 'Resource') {
      // This is a Deny statement that is not all resources, so it's not a match
      return {
        resource: policyResource.value(),
        matches: false,
        mismatchReason: 'requestAllResourcesDenySpecificResource'
      }
    } else if (effect === 'Deny' && resourceType === 'NotResource') {
      return {
        resource: policyResource.value(),
        matches: true // This gets inverted in the caller
      }
    }
    throw new Error(`Unknown Resource Type and Effect Combination: ${resourceType} ${effect}`)
  }

  // Request contains wildcards but neither is a full *
  if (request.resource.hasWildcards() && policyResource.isArnResource()) {
    const overlaps = [
      resourcePatternOverlap(policyResource.partition(), request.resource.partition()),
      resourcePatternOverlap(policyResource.service(), request.resource.service()),
      resourcePatternOverlap(policyResource.region(), request.resource.region()),
      resourcePatternOverlap(policyResource.account(), request.resource.account()),
      resourcePatternOverlap(policyResource.resource(), request.resource.resource())
    ]

    if (resourceType === 'Resource' && effect === 'Allow') {
      if (overlaps.every((o) => o !== 'none')) {
        return {
          resource: policyResource.value(),
          matches: true
        }
      }
    } else if (resourceType === 'Resource' && effect === 'Deny') {
      if (overlaps.some((o) => o === 'none' || o === 'policy_is_subset')) {
        return {
          resource: policyResource.value(),
          matches: false,
          mismatchReason: 'resourcePatternMismatch'
        }
      }
    } else if (resourceType === 'NotResource' && effect === 'Allow') {
      /*
       * For an Allow/NotResource Statement:
          - If the resolved string matches the request resource, it is not a match
          - If the resolved string is a superset of the request resource, it is not a match
          - If the resolved string is a subset of the request resource, it is a match
          - If there is no overlap at all between the resolved string and the request resource, it is a match
       */
      if (overlaps.every((o) => o === 'equal' || o === 'policy_is_superset')) {
        return {
          resource: policyResource.value(),
          // This gets inverted in the caller
          matches: true
        }
      } else {
        return {
          resource: policyResource.value(),
          // This gets inverted in the caller
          matches: false,
          mismatchReason: 'resourcePatternMismatch'
        }
      }
    } else if (resourceType === 'NotResource' && effect === 'Deny') {
      /*
        For a Deny/NotResource Statement:
        - If the resolved string matches the request resource, it is not a match
        - If the resolved string is a superset of the request resource, it is not a match
        - If the resolved string is a subset of the request resource, it is not a match
        - If there is no overlap at all between the resolved string and the request resource, it is a match
      */
      if (overlaps.some((o) => o === 'none')) {
        return {
          resource: policyResource.value(),
          // This gets inverted in the caller
          matches: false,
          mismatchReason: 'resourcePatternMismatch'
        }
      } else {
        return {
          resource: policyResource.value(),
          // This gets inverted in the caller
          matches: true
        }
      }
    } else {
      throw new Error(`Unknown Resource Type and Effect Combination: ${resourceType} ${effect}`)
    }
  }

  if (policyResource.isArnResource()) {
    if (!request.resource) {
      return {
        resource: policyResource.value(),
        matches: false,
        errors: ['Request does not have a resource'],
        mismatchReason: 'requestMissingResource'
      }
    }

    const resource = request.resource
    if (!convertResourceSegmentToRegex(policyResource.partition()).test(resource.partition())) {
      return {
        resource: policyResource.value(),
        matches: false,
        errors: ['Partition does not match'],
        mismatchReason: 'partitionMismatch'
      }
    }

    if (!convertResourceSegmentToRegex(policyResource.service()).test(resource.service())) {
      return {
        resource: policyResource.value(),
        matches: false,
        errors: ['Service does not match'],
        mismatchReason: 'serviceMismatch'
      }
    }

    if (!convertResourceSegmentToRegex(policyResource.region()).test(resource.region())) {
      return {
        resource: policyResource.value(),
        matches: false,
        errors: ['Region does not match'],
        mismatchReason: 'regionMismatch'
      }
    }

    if (!convertResourceSegmentToRegex(policyResource.account()).test(resource.account())) {
      return {
        resource: policyResource.value(),
        matches: false,
        errors: ['Account does not match'],
        mismatchReason: 'accountMismatch'
      }
    }

    //Wildcards and variables are not allowed in the product segment https://docs.aws.amazon.com/IAM/latest/UserGuide/reference-arns.html "Incorrect wildcard usage"
    const [policyProduct, policyResourceId] = getResourceSegments(policyResource)
    if (!resource.resource().startsWith(policyProduct)) {
      return {
        resource: policyResource.value(),
        matches: false,
        errors: ['Product does not match'],
        mismatchReason: 'productMismatch'
      }
    }

    const requestResourceId = resource.resource().slice(policyProduct.length)
    const { pattern, errors } = convertIamString(policyResourceId, request)
    const resolvedResourceId = convertIamString(policyResourceId, request, {
      convertToRegex: false,
      replaceWildcards: false
    })
    const resolvedResource =
      policyResource.value().slice(0, policyResource.value().length - policyResourceId.length) +
      resolvedResourceId
    const resolvedValue = resolvedResource === policyResource.value() ? undefined : resolvedResource

    if (!pattern.test(requestResourceId)) {
      const mismatchReason = errors?.length ? 'unresolvablePolicyVariable' : 'resourceIdMismatch'
      return {
        resource: policyResource.value(),
        matches: false,
        errors,
        mismatchReason,
        resolvedValue
      }
    }

    return {
      resource: policyResource.value(),
      matches: true,
      resolvedValue
    }
  } else {
    throw new Error('Unknown resource type')
  }
}

/**
 * Determines if the policy string is equal to, a subset of, a superset of,
 * or has no overlap with the request string.
 *
 * @param policyString the policy string to use
 * @param requestString the request string to compare to the policy string
 * @returns 'equal' if the strings are equal, 'subset' if the policy string is a subset of the request string, 'superset' if the policy string is a superset of the request string, 'overlap' if the strings have a non-empty intersection but neither contains the other, or 'none' if there is no overlap
 */
export function resourcePatternOverlap(
  policyString: string,
  requestString: string
): 'equal' | 'policy_is_subset' | 'policy_is_superset' | 'overlap' | 'none' {
  if (policyString === requestString) {
    return 'equal'
  }
  const requestPattern = requestResourcePatternToRegexString(requestString)
  if (policyString.match(requestPattern)) {
    return 'policy_is_subset'
  }

  const policyPattern = policyResourcePatternToRegexString(policyString)
  if (requestString.match(policyPattern)) {
    return 'policy_is_superset'
  }

  if (resourcePatternsIntersect(policyString, requestString)) {
    return 'overlap'
  }

  return 'none'
}

/**
 * Checks whether a policy resource pattern and request resource pattern share
 * at least one concrete resource string.
 *
 * Policy patterns use IAM `*` and `?` wildcards. Request patterns only treat
 * `*` as a wildcard; `?` remains literal to match the existing request
 * wildcard semantics in this module.
 *
 * @param policyString the policy-side resource pattern segment to compare
 * @param requestString the request-side resource pattern segment to compare
 * @returns true when the patterns have a non-empty intersection
 */
function resourcePatternsIntersect(policyString: string, requestString: string): boolean {
  const policyPattern = [...policyString]
  const requestPattern = [...requestString]
  const visited = new Set<string>()
  const queue: Array<[number, number]> = [[0, 0]]
  const key = (policyIndex: number, requestIndex: number) => `${policyIndex},${requestIndex}`

  while (queue.length > 0) {
    const [policyIndex, requestIndex] = queue.shift()!
    const stateKey = key(policyIndex, requestIndex)
    if (visited.has(stateKey)) {
      continue
    }
    visited.add(stateKey)

    if (policyIndex === policyPattern.length && requestIndex === requestPattern.length) {
      return true
    }

    const policyToken = tokenAt(policyPattern, policyIndex)
    const requestToken = tokenAt(requestPattern, requestIndex)

    if (policyToken === '*') {
      queue.push([policyIndex + 1, requestIndex])
    }
    if (requestToken === '*') {
      queue.push([policyIndex, requestIndex + 1])
    }

    if (resourcePatternTokensCanConsumeSameCharacter(policyToken, requestToken)) {
      const nextPolicyIndexes = nextResourcePatternIndexesAfterOneCharacter(
        policyPattern,
        policyIndex,
        true
      )
      const nextRequestIndexes = nextResourcePatternIndexesAfterOneCharacter(
        requestPattern,
        requestIndex,
        false
      )
      for (const nextPolicyIndex of nextPolicyIndexes) {
        for (const nextRequestIndex of nextRequestIndexes) {
          queue.push([nextPolicyIndex, nextRequestIndex])
        }
      }
    }
  }

  return false
}

/**
 * Reads a token from a pattern, returning null at the end of the pattern.
 *
 * @param pattern the pattern characters
 * @param index the index to read
 * @returns the token at the index, or null when the index is past the end
 */
function tokenAt(pattern: string[], index: number): string | null {
  return index < pattern.length ? pattern[index] : null
}

/**
 * Determines whether policy and request pattern tokens can match the same next
 * concrete character under their respective wildcard semantics.
 *
 * @param policyToken token from the policy pattern, where `*` and `?` are wildcards
 * @param requestToken token from the request pattern, where only `*` is a wildcard
 * @returns true if both tokens can consume the same concrete character
 */
function resourcePatternTokensCanConsumeSameCharacter(
  policyToken: string | null,
  requestToken: string | null
): boolean {
  if (policyToken === null || requestToken === null) {
    return false
  }

  const policyWildcard = policyToken === '*' || policyToken === '?'
  const requestWildcard = requestToken === '*'
  if (!policyWildcard && !requestWildcard) {
    return policyToken === requestToken
  }

  return true
}

/**
 * Returns possible next indexes after consuming one concrete character from a pattern.
 *
 * @param pattern the pattern characters
 * @param index current pattern index
 * @param questionMarkIsWildcard whether `?` should be treated as a one-character wildcard
 * @returns possible next indexes after one concrete character is consumed
 */
function nextResourcePatternIndexesAfterOneCharacter(
  pattern: string[],
  index: number,
  questionMarkIsWildcard: boolean
): number[] {
  const token = tokenAt(pattern, index)
  if (token === null) {
    return []
  }
  if (token === '*') {
    return [index]
  }
  if (token === '?' && questionMarkIsWildcard) {
    return [index + 1]
  }
  return [index + 1]
}
