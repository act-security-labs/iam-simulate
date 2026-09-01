import { iamActionDetails } from '@actsecurity/iam-data'
import { type Resource } from '@actsecurity/iam-policy'
import { type AwsRequest } from './request/request.js'

const matchesNothing = new RegExp('a^')

export interface StringReplaceOptions {
  replaceWildcards: boolean
  convertToRegex: boolean
}

const defaultStringReplaceOptions: StringReplaceOptions = {
  replaceWildcards: true,
  convertToRegex: true
}

/**
 * This will convert a string to a regex that can be used to match against a string.
 * This will replace any variables in the string with the value of the variable in the request context.
 *
 * @param value the string to convert to a regex
 * @param requestContext the request context to get the variable values from
 * @returns a regex that can be used to match against a string
 */
export function convertIamString(
  value: string,
  request: AwsRequest,
  replaceOptions: { replaceWildcards?: boolean; convertToRegex: false }
): string
export function convertIamString(
  value: string,
  request: AwsRequest,
  replaceOptions?: Partial<StringReplaceOptions>
): { pattern: RegExp; errors?: string[] }
export function convertIamString(
  value: string,
  request: AwsRequest,
  replaceOptions?: Partial<StringReplaceOptions>
): { pattern: RegExp; errors?: string[] } | string {
  const options = { ...defaultStringReplaceOptions, ...replaceOptions }

  const errors: string[] = []
  const newValue = replaceIamStringTokens(value, request, options, errors)

  if (!options.convertToRegex) {
    return newValue
  }

  if (errors.length > 0) {
    return { pattern: matchesNothing, errors }
  }

  return { pattern: new RegExp('^' + newValue + '$') }
}

/**
 * Replace IAM wildcard and variable tokens while escaping literal spans for regex conversion.
 *
 * @param value the IAM string value to convert
 * @param request the request context used to resolve policy variables
 * @param options controls wildcard replacement and regex conversion behavior
 * @param errors collects variable resolution errors that make the value unable to match
 * @returns the converted IAM string or regex source fragment
 */
function replaceIamStringTokens(
  value: string,
  request: AwsRequest,
  options: StringReplaceOptions,
  errors: string[]
): string {
  let newValue = ''
  let literalStart = 0
  let index = 0

  while (index < value.length) {
    const character = value[index]

    if (character == '*' || character == '?') {
      newValue += replaceLiteralSpan(value.slice(literalStart, index), options)
      newValue += replaceIamStringToken(character, request, options, errors)
      index++
      literalStart = index
    } else if (character == '$' && value[index + 1] == '{') {
      const variableEndIndex = value.indexOf('}', index + 2)

      if (variableEndIndex == -1) {
        index++
      } else {
        newValue += replaceLiteralSpan(value.slice(literalStart, index), options)
        newValue += replaceIamStringToken(
          value.slice(index, variableEndIndex + 1),
          request,
          options,
          errors
        )
        index = variableEndIndex + 1
        literalStart = index
      }
    } else {
      index++
    }
  }

  newValue += replaceLiteralSpan(value.slice(literalStart), options)
  return newValue
}

/**
 * Escape a literal IAM string span when producing a regular expression.
 *
 * @param literal the literal IAM string span outside wildcard and variable tokens
 * @param options controls whether regex conversion is enabled
 * @returns the literal span escaped for regex conversion, or unchanged for raw string conversion
 */
function replaceLiteralSpan(literal: string, options: StringReplaceOptions): string {
  return options.convertToRegex ? escapeRegexCharacters(literal) : literal
}

/**
 * Replace a single IAM string token with its regex or raw string representation.
 *
 * @param match the IAM token to replace
 * @param request the request context used to resolve policy variables
 * @param options controls wildcard replacement and regex conversion behavior
 * @param errors collects variable resolution errors that make the value unable to match
 * @returns the token replacement value
 */
function replaceIamStringToken(
  match: string,
  request: AwsRequest,
  options: StringReplaceOptions,
  errors: string[]
): string {
  if (match == '?') {
    return replacementValue(match, '\\?', '.', options)
  } else if (match == '*') {
    return replacementValue(match, '\\*', '.*?', options)
  } else if (match == '${*}') {
    return replacementValue(match, '\\$\\{\\*\\}', '\\*', options)
  } else if (match == '${?}') {
    return replacementValue(match, '\\$\\{\\?\\}', '\\?', options)
  } else if (match == '${$}') {
    return replacementValue(match, '\\$\\{\\$\\}', '\\$', options)
  }

  //This means it's a variable
  const inTheBrackets = match.slice(2, -1)

  let defaultValue = undefined
  const defaultParts = inTheBrackets.split(', ')
  if (defaultParts.length == 2) {
    const segmentAfterComma = defaultParts.at(1)
    if (segmentAfterComma?.startsWith("'") && segmentAfterComma.endsWith("'")) {
      defaultValue = segmentAfterComma.slice(1, -1)
    }
  }
  const variableName = defaultParts.at(0)!.trim()

  const { value: requestValue, error: requestValueError } = getContextSingleValue(
    request,
    variableName
  )

  if (requestValue) {
    //TODO: Maybe escape the * in the resolved value to ${*}
    return options.convertToRegex ? escapeRegexCharacters(requestValue) : requestValue
  } else if (defaultValue) {
    /*
      TODO: What happens in a request if a multi value context key is used in a string and there
      is a default value? Will it use the default value or will it fail the condition test?
    */
    //TODO: Maybe escape the * in the resolved value to ${*}
    return options.convertToRegex ? escapeRegexCharacters(defaultValue) : defaultValue
  } else {
    if (requestValueError == 'missing') {
      errors.push(
        `{${variableName}} not found in request context, and no default value provided. This will never match`
      )
    } else if (requestValueError == 'multivalue') {
      errors.push(
        `{${variableName}} is a multi value context key, and cannot be used for replacement. This will never match`
      )
    }
    /*
    https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_variables.html#policy-vars-no-value
    */
    return match
  }
}

/**
 * Replace regex characters in a string with their escaped versions
 *
 * @param str the string to escape regex characters in
 * @returns the string with regex characters escaped
 */
function escapeRegexCharacters(str: string): string {
  let escaped = ''

  for (const character of str) {
    if (isRegexMetacharacter(character)) {
      escaped += '\\'
    }
    escaped += character
  }

  return escaped
}

/**
 * Check if a character has special meaning in a regular expression pattern.
 *
 * @param character the character to check
 * @returns whether the character must be escaped for literal regex matching
 */
function isRegexMetacharacter(character: string): boolean {
  return (
    character == '.' ||
    character == '*' ||
    character == '+' ||
    character == '?' ||
    character == '^' ||
    character == '$' ||
    character == '{' ||
    character == '}' ||
    character == '(' ||
    character == ')' ||
    character == '|' ||
    character == '[' ||
    character == ']' ||
    character == '\\'
  )
}

/**
 * Get the string value of a context key only if it is a single value key
 *
 * @param requestContext the request context to get the value from
 * @param contextKeyName the name of the context key to get the value of
 * @returns the value of the context key if it is a single value key, undefined otherwise
 */
function getContextSingleValue(
  request: AwsRequest,
  contextKeyName: string
): { value?: string; error?: 'missing' | 'multivalue' } {
  if (!request.contextKeyExists(contextKeyName)) {
    return {
      error: 'missing'
    }
  }
  const keyValue = request.getContextKeyValue(contextKeyName)
  if (keyValue.isStringValue()) {
    return { value: keyValue.value }
  }

  return { error: 'multivalue' }
}

/**
 * Get the replacement value for a string
 *
 * @param original the original IAM token text
 * @param escaped the regex-escaped literal representation of the token
 * @param regex the regex wildcard representation of the token
 * @param options controls wildcard replacement and regex conversion behavior
 * @returns the token replacement value
 */
function replacementValue(
  original: string,
  escaped: string,
  regex: string,
  options: StringReplaceOptions
): string {
  if (!options.convertToRegex) {
    return original
  }
  if (options.replaceWildcards) {
    return regex
  }
  return escaped
}

export interface ArnParts {
  partition: string | undefined
  service: string | undefined
  region: string | undefined
  accountId: string | undefined
  resource: string | undefined
  // resourceType: string | undefined
  // resourcePath: string | undefined
}

/**
 * Split an ARN into its parts
 *
 * @param arn the arn to split
 * @returns the parts of the ARN
 */
export function splitArnParts(arn: string): ArnParts {
  const parts = arn.split(':')
  const partition = parts.at(1)
  const service = parts.at(2)
  const region = parts.at(3)
  const accountId = parts.at(4)
  const resource = parts.slice(5).join(':')

  return {
    partition,
    service,
    region,
    accountId,
    resource
  }
}

/**
 * Get the product/id segments of the resource portion of an ARN.
 * The first segment is the product segment and the second segment is the resource id segment.
 * This could be split by a colon or a slash, so it checks for both. It also checks for S3 buckets/objects.
 *
 * @param resource The resource to get the resource segments. Must be an ARN resource.
 * @returns a tuple with the first segment being the product segment (including the separator) and the second segment being the resource id.
 */
export function getResourceSegments(resource: Resource): [string, string] {
  if (!resource.isArnResource()) {
    throw new Error(`Resource ${resource.value()} is not an ARN resource`)
  }

  const resourceString = resource.resource()

  // This is terrible, and I hate it
  if (resource.service() === 's3' && resource.account() === '' && resource.region() === '') {
    return ['', resourceString]
  }

  const slashIndex = resourceString.indexOf('/')
  const colonIndex = resourceString.indexOf(':')

  let splitIndex = slashIndex
  if (slashIndex != -1 && colonIndex != -1) {
    splitIndex = Math.min(slashIndex, colonIndex) + 1
  } else if (colonIndex == -1) {
    splitIndex = slashIndex + 1
  } else if (slashIndex == -1) {
    splitIndex = colonIndex + 1
  } else {
    throw new Error(`Unable to split resource ${resource}`)
  }

  return [resourceString.slice(0, splitIndex), resourceString.slice(splitIndex)]
}

/**
 * Checks if a value is defined and not null and narrows the type to the defined type
 *
 * @param value the value to check if it is defined
 * @returns if the value is defined and not null
 */
export function isDefined<T>(value: T | undefined): value is T {
  return value !== undefined && value !== null
}

/**
 * Checks if a value is not defined or null
 *
 * @param value the value to check if it is not defined
 * @returns if the value is not defined or null
 */
export function isNotDefined<T>(value: T | undefined): value is undefined {
  return !isDefined(value)
}

/**
 * Checks if an action is a wildcard only action
 *
 * @param service the service the action belongs to
 * @param action the action to check if it is a wildcard only action
 * @returns if the action is a wildcard only action
 * @throws an error if the service or action does not exist
 */
export async function isWildcardOnlyAction(service: string, action: string): Promise<boolean> {
  const actionDetails = await iamActionDetails(service, action)
  return actionDetails.resourceTypes.length === 0
}

/**
 * Lowercase all strings in an array
 *
 * @param strings the strings to lowercase
 * @returns the lowercased strings
 */
export function lowerCaseAll(strings: string[]): string[] {
  return strings.map((s) => s.toLowerCase())
}

/**
 * Gets the IAM variables from a string
 *
 * @param value the string to get the variables from
 * @returns the variables in the string, if any
 */
export function getVariablesFromString(value: string): string[] {
  const matches = value.match(/\$\{.*?\}/g)
  if (matches) {
    return matches.map((m) => {
      const inBrackets = m.slice(2, -1)
      if (inBrackets.includes(',')) {
        return inBrackets.split(',')[0].trim()
      }
      return inBrackets
    })
  }
  return []
}

/**
 * Checks to see if an ARN is an S3 bucket or object ARN
 *
 * @param arn the ARN to check
 * @returns whether the ARN is an S3 bucket or object ARN
 */
export function isS3BucketOrObjectArn(arn: string): boolean {
  const arnParts = splitArnParts(arn)
  if (arnParts.service !== 's3') {
    return false
  }
  if (!arnParts.resource) {
    return false
  }
  // S3 bucket or object ARNs have no account ID or region
  if (arnParts.accountId || arnParts.region) {
    return false
  }
  return true
}
