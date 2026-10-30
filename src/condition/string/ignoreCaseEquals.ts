/**
 * Compare strings using the case behavior observed in AWS IAM's policy simulator.
 *
 * Lowercase each UTF-16 code unit independently, rather than applying Unicode case
 * folding or lowercasing whole strings. This is an empirical approximation: the
 * mappings depend on the JavaScript runtime's Unicode version.
 *
 * @param left the first string to compare
 * @param right the second string to compare
 * @returns whether the strings compare equal ignoring case
 */
export function ignoreCaseEquals(left: string, right: string): boolean {
  return lowerCodeUnits(left) === lowerCodeUnits(right)
}

/**
 * Lowercase individual UTF-16 code units, including mappings that expand to multiple units.
 *
 * @param value the string to transform
 * @returns the concatenation of the lowercase code units
 */
function lowerCodeUnits(value: string): string {
  let result = ''
  for (let index = 0; index < value.length; index++) {
    result += value[index].toLowerCase()
  }
  return result
}
