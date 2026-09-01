import { type Policy, type Statement } from '@actsecurity/iam-policy'
import { splitArnParts } from '../../util.js'

/**
 * Caller-supplied S3 Block Public Access settings for simulation.
 */
export interface S3ServiceSettings {
  /**
   * Whether S3 Block Public Access is enabled for the request target.
   */
  blockPublicAccess?: boolean
}

/**
 * Classification of a standard S3 bucket policy for runtime RestrictPublicBuckets behavior.
 */
export type S3RuntimePublicPolicyClassification =
  | {
      /**
       * The bucket policy is public for runtime RestrictPublicBuckets behavior.
       */
      result: 'public'

      /**
       * Allow statements that make the policy public.
       */
      publicStatements: S3RuntimePublicStatement[]
    }
  | {
      /**
       * The bucket policy is not public for runtime RestrictPublicBuckets behavior.
       */
      result: 'nonPublic'
    }

/**
 * Identifies an Allow statement that makes a bucket policy public.
 */
export interface S3RuntimePublicStatement {
  /**
   * The 1-based statement index in the policy.
   */
  index: number

  /**
   * The statement Sid, if present.
   */
  sid?: string
}

/**
 * Classifies a standard S3 bucket policy as public or non-public for runtime
 * RestrictPublicBuckets behavior.
 *
 * @param policy the loaded S3 bucket policy to classify
 * @returns whether the policy is runtime-public and, when public, the public statements
 */
export function classifyS3RuntimePublicBucketPolicy(
  policy: Policy<unknown>
): S3RuntimePublicPolicyClassification {
  const publicStatements = policy
    .statements()
    .filter((statement) => statement.isAllow() && statementIsRuntimePublic(statement))
    .map((statement) => statementIdentifier(statement))

  if (publicStatements.length > 0) {
    return { result: 'public', publicStatements }
  }

  return { result: 'nonPublic' }
}

/**
 * Determines whether an individual Allow statement makes a bucket policy runtime-public.
 *
 * @param statement the statement to classify
 * @returns true if the statement is public for runtime RestrictPublicBuckets behavior
 */
function statementIsRuntimePublic(statement: Statement): boolean {
  if (!statement.isPrincipalStatement()) {
    return true
  }

  const principals = statement.principals()
  if (principals.some((principal) => principal.isWildcardPrincipal())) {
    return !hasPublicAccessLimitingCondition(statement)
  }

  return false
}

/**
 * Gets the statement index and Sid for classifier output.
 *
 * @param statement the statement to identify
 * @returns the statement index and optional Sid
 */
function statementIdentifier(statement: Statement): S3RuntimePublicStatement {
  return {
    index: statement.index(),
    ...(statement.sid() ? { sid: statement.sid() } : {})
  }
}

/**
 * Determines whether a wildcard-principal statement has a condition that limits access
 * enough to be non-public for S3 BPA runtime classification.
 *
 * @param statement the wildcard-principal statement to inspect
 * @returns true if a supported condition makes the statement non-public
 */
function hasPublicAccessLimitingCondition(statement: Statement): boolean {
  const conditionMap = statement.conditionMap()
  if (!conditionMap) {
    return false
  }

  return (
    hasFixedValueCondition(conditionMap, 'aws:PrincipalOrgID') ||
    hasFixedValueCondition(conditionMap, 'aws:PrincipalAccount') ||
    hasPrincipalArnLimitingCondition(conditionMap) ||
    hasOrgPathLimitingCondition(conditionMap, 'aws:PrincipalOrgPaths') ||
    hasAwsServicePrincipalLimitingCondition(conditionMap) ||
    hasPrincipalServiceNameLimitingCondition(conditionMap) ||
    hasUseridLimitingCondition(conditionMap) ||
    hasFixedValueCondition(conditionMap, 'aws:SourceVpce') ||
    hasFixedValueCondition(conditionMap, 'aws:SourceVpc') ||
    hasSourceVpcArnLimitingCondition(conditionMap) ||
    hasFixedValueCondition(conditionMap, 'aws:VpceAccount') ||
    hasFixedValueCondition(conditionMap, 'aws:VpceOrgID') ||
    hasOrgPathLimitingCondition(conditionMap, 'aws:VpceOrgPaths') ||
    hasSourceIpLimitingCondition(conditionMap) ||
    hasFixedArnCondition(conditionMap, 'aws:SourceArn') ||
    hasFixedValueCondition(conditionMap, 'aws:SourceAccount')
  )
}

/**
 * Checks for exact fixed-value conditions for account, org, VPC, and similar keys.
 *
 * @param conditionMap the statement condition map
 * @param key the condition key to inspect
 * @returns true if the key is constrained to fixed values by supported operators
 */
function hasFixedValueCondition(
  conditionMap: Record<string, Record<string, string[]>>,
  key: string
): boolean {
  return conditionEntries(conditionMap, key).some(
    ({ operator, values }) =>
      ['StringEquals', 'StringEqualsIgnoreCase', 'ForAnyValue:StringEquals'].includes(operator) ||
      (operator === 'StringLike' && values.every((value) => !hasWildcard(value)))
  )
}

/**
 * Checks for public-access-limiting aws:PrincipalArn conditions.
 *
 * @param conditionMap the statement condition map
 * @returns true if PrincipalArn is constrained to a fixed account principal pattern
 */
function hasPrincipalArnLimitingCondition(
  conditionMap: Record<string, Record<string, string[]>>
): boolean {
  return conditionEntries(conditionMap, 'aws:PrincipalArn').some(({ operator, values }) => {
    if (operator === 'ArnEquals') {
      return values.every(isArnWithFixedAccount)
    }
    if (operator === 'ArnLike') {
      return values.every(
        (value) => isArnWithFixedAccount(value) && arnWildcardOnlyInResource(value)
      )
    }
    return false
  })
}

/**
 * Checks for exact SourceVpcArn conditions.
 *
 * @param conditionMap the statement condition map
 * @returns true if SourceVpcArn is constrained to exact ARNs
 */
function hasSourceVpcArnLimitingCondition(
  conditionMap: Record<string, Record<string, string[]>>
): boolean {
  return hasFixedArnCondition(conditionMap, 'aws:SourceVpcArn')
}

/**
 * Checks for fixed ARN conditions.
 *
 * @param conditionMap the statement condition map
 * @param key the condition key to inspect
 * @returns true if the key is constrained to fixed ARN values
 */
function hasFixedArnCondition(
  conditionMap: Record<string, Record<string, string[]>>,
  key: string
): boolean {
  return conditionEntries(conditionMap, key).some(
    ({ operator, values }) => operator === 'ArnEquals' && values.every(isArnWithFixedAccount)
  )
}

/**
 * Checks for AWS Organizations path conditions with fixed org path prefixes.
 *
 * @param conditionMap the statement condition map
 * @param key the condition key to inspect
 * @returns true if the path condition is fixed or uses a documented suffix wildcard shape
 */
function hasOrgPathLimitingCondition(
  conditionMap: Record<string, Record<string, string[]>>,
  key: string
): boolean {
  return conditionEntries(conditionMap, key).some(({ operator, values }) => {
    if (operator === 'StringEquals') {
      return values.every(isFixedOrgPath)
    }
    if (operator === 'StringLike') {
      return values.every(isFixedOrgPathWithOptionalSuffixWildcard)
    }
    return false
  })
}

/**
 * Checks for conditions that limit access to AWS service principals.
 *
 * @param conditionMap the statement condition map
 * @returns true if the statement is limited to AWS service principals
 */
function hasAwsServicePrincipalLimitingCondition(
  conditionMap: Record<string, Record<string, string[]>>
): boolean {
  return conditionEntries(conditionMap, 'aws:PrincipalIsAWSService').some(
    ({ operator, values }) =>
      ['Bool', 'StringEquals', 'StringEqualsIgnoreCase', 'StringLike'].includes(operator) &&
      values.every((value) => value.toLowerCase() === 'true')
  )
}

/**
 * Checks for service-principal name conditions.
 *
 * @param conditionMap the statement condition map
 * @returns true if the statement is limited to service principal names
 */
function hasPrincipalServiceNameLimitingCondition(
  conditionMap: Record<string, Record<string, string[]>>
): boolean {
  return ['aws:PrincipalServiceName', 'aws:PrincipalServiceNamesList'].some((key) =>
    conditionEntries(conditionMap, key).some(({ operator, values }) => {
      return (
        [
          'StringEquals',
          'ForAnyValue:StringEquals',
          'StringLike',
          'ForAnyValue:StringLike'
        ].includes(operator) && values.every(isServiceNamePattern)
      )
    })
  )
}

/**
 * Checks for aws:userid conditions with a fixed stable ID prefix.
 *
 * @param conditionMap the statement condition map
 * @returns true if userid is constrained to exact values or fixed-prefix session suffix wildcards
 */
function hasUseridLimitingCondition(
  conditionMap: Record<string, Record<string, string[]>>
): boolean {
  return conditionEntries(conditionMap, 'aws:userid').some(({ operator, values }) => {
    if (operator === 'StringEquals') {
      return values.every((value) => !hasWildcard(value))
    }
    if (operator === 'StringLike') {
      return values.every((value) => /^[A-Z0-9]+:\*$/.test(value))
    }
    return false
  })
}

/**
 * Checks for sufficiently narrow aws:SourceIp conditions.
 *
 * @param conditionMap the statement condition map
 * @returns true if SourceIp ranges are narrow enough to be non-public
 */
function hasSourceIpLimitingCondition(
  conditionMap: Record<string, Record<string, string[]>>
): boolean {
  return conditionEntries(conditionMap, 'aws:SourceIp').some(
    ({ operator, values }) => operator === 'IpAddress' && values.every(sourceIpRangeIsNonPublic)
  )
}

/**
 * Gets condition entries for a key using case-insensitive key matching.
 *
 * @param conditionMap the statement condition map
 * @param key the condition key to inspect
 * @returns matching condition entries
 */
function conditionEntries(
  conditionMap: Record<string, Record<string, string[]>>,
  key: string
): Array<{ operator: string; values: string[] }> {
  const entries: Array<{ operator: string; values: string[] }> = []
  for (const [operator, keyValues] of Object.entries(conditionMap)) {
    for (const [conditionKey, values] of Object.entries(keyValues)) {
      if (conditionKey.toLowerCase() === key.toLowerCase()) {
        entries.push({ operator, values })
      }
    }
  }
  return entries
}

/**
 * Checks whether an ARN pattern has a fixed account component.
 *
 * @param value the ARN or ARN pattern to inspect
 * @returns true if the account component is fixed and non-wildcard
 */
function isArnWithFixedAccount(value: string): boolean {
  const arn = splitArnParts(value)
  return !!arn.accountId && !hasWildcard(arn.accountId)
}

/**
 * Checks whether ARN wildcards are limited to the resource component.
 *
 * @param value the ARN pattern to inspect
 * @returns true if partition, service, region, and account are fixed
 */
function arnWildcardOnlyInResource(value: string): boolean {
  const arn = splitArnParts(value)
  return ![arn.partition, arn.service, arn.region, arn.accountId].some((part) =>
    part ? hasWildcard(part) : false
  )
}

/**
 * Checks whether a string has IAM wildcard characters.
 *
 * @param value the value to inspect
 * @returns true if the value contains `*` or `?`
 */
function hasWildcard(value: string): boolean {
  return value.includes('*') || value.includes('?')
}

/**
 * Checks whether an Organizations path has a fixed org/root path prefix.
 *
 * @param value the org path value to inspect
 * @returns true if the value is fixed and starts with an org path
 */
function isFixedOrgPath(value: string): boolean {
  return /^o-[a-z0-9]+\/[^*?]+/.test(value) && !hasWildcard(value)
}

/**
 * Checks whether an Organizations path is fixed or uses a suffix wildcard.
 *
 * @param value the org path value to inspect
 * @returns true if the value has a fixed org path prefix and optional trailing wildcard
 */
function isFixedOrgPathWithOptionalSuffixWildcard(value: string): boolean {
  if (!value.endsWith('*')) {
    return isFixedOrgPath(value)
  }
  const prefix = value.slice(0, -1)
  return /^o-[a-z0-9]+\/[^*?]+/.test(prefix) && !hasWildcard(prefix)
}

/**
 * Checks whether a value is an AWS service-name pattern.
 *
 * @param value the service name or pattern to inspect
 * @returns true if the value is an amazonaws.com service name pattern
 */
function isServiceNamePattern(value: string): boolean {
  return /^([a-z0-9-]+|\*)\.(amazonaws\.com|amazonaws\.com\.cn)$/.test(value)
}

/**
 * Determines whether a SourceIp CIDR is narrow/private enough to be non-public.
 *
 * @param cidr the CIDR value to inspect
 * @returns true if the CIDR is non-public for S3 BPA classification
 */
function sourceIpRangeIsNonPublic(cidr: string): boolean {
  const [address, prefixString] = cidr.split('/')
  const prefix = Number(prefixString)
  if (!address || !Number.isInteger(prefix)) {
    return false
  }

  if (address.includes(':')) {
    return prefix >= 32
  }

  const firstOctet = Number(address.split('.')[0])
  const secondOctet = Number(address.split('.')[1])
  if (!Number.isInteger(firstOctet) || !Number.isInteger(secondOctet)) {
    return false
  }

  if (
    firstOctet === 10 ||
    (firstOctet === 172 && secondOctet >= 16 && secondOctet <= 31) ||
    (firstOctet === 192 && secondOctet === 168)
  ) {
    return true
  }

  return prefix >= 8
}
