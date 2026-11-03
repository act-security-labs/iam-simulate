/**
 * Compare two already-resolved IAM condition values using JavaScript strict string equality.
 * This does not resolve variables or evaluate wildcards.
 *
 * @param left the first literal value
 * @param right the second literal value
 * @returns whether the values are identical
 */
export function iamStringEquals(left: string, right: string): boolean {
  return left === right
}

/**
 * Compare already-resolved literal strings using the case behavior observed in AWS IAM's policy simulator.
 * This does not resolve policy variables or evaluate condition operators.
 *
 * Lowercase each UTF-16 code unit independently, rather than applying Unicode case
 * folding or lowercasing whole strings. This is an empirical approximation: the
 * mappings depend on the JavaScript runtime's Unicode version.
 *
 * @param left the first string to compare
 * @param right the second string to compare
 * @returns whether the strings compare equal ignoring case
 */
export function iamStringEqualsIgnoreCase(left: string, right: string): boolean {
  return (
    iamStringEqualsNormalizeCaseInsensitive(left) === iamStringEqualsNormalizeCaseInsensitive(right)
  )
}

/** Internal alias retained for the IAM string condition operators. */
export const ignoreCaseEquals = iamStringEqualsIgnoreCase

/**
 * Normalize an already-resolved IAM string value for case-insensitive equality or indexing.
 * Lowercases individual UTF-16 code units, including mappings that expand to multiple units.
 * This is distinct from context-key normalization and depends on runtime Unicode mappings.
 *
 * @param value the string to transform
 * @returns the concatenation of the lowercase code units
 */
export function iamStringEqualsNormalizeCaseInsensitive(value: string): string {
  let result = ''
  for (let index = 0; index < value.length; index++) {
    result += value[index].toLowerCase()
  }
  return result
}
