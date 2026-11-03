import { describe, expect, it } from 'vitest'
import {
  iamStringEquals,
  iamStringEqualsIgnoreCase,
  iamStringEqualsNormalizeCaseInsensitive
} from '../../index.js'

describe('IAM literal string comparison helpers', () => {
  it('compares already-resolved values exactly for case-sensitive equality', () => {
    //Given literal strings, including regex metacharacters and a trailing newline
    //When comparing them
    //Then only identical strings match
    expect(iamStringEquals('a.*', 'a.*')).toBe(true)
    expect(iamStringEquals('a.*', 'abc')).toBe(false)
    expect(iamStringEquals('Role', 'role')).toBe(false)
    expect(iamStringEquals('x', 'x\n')).toBe(false)
    expect(iamStringEquals('', '')).toBe(true)
  })

  it.each([
    ['İ', 'i\u0307', true],
    ['İ', 'i', false],
    ['σ', 'ς', false],
    ['K', 'K', true],
    ['𐐀', '𐐨', false],
    ['', '', true],
    ['Tag', 'tAG', true]
  ])('ignore case compares %j and %j using IAM string-value semantics', (left, right, expected) => {
    //Given two literal condition values
    //When comparing and normalizing them
    const equal = iamStringEqualsIgnoreCase(left, right)
    const normalizedEqual =
      iamStringEqualsNormalizeCaseInsensitive(left) ===
      iamStringEqualsNormalizeCaseInsensitive(right)

    //Then both methods use the same AWS-observed per-code-unit mapping
    expect(equal).toBe(expected)
    expect(normalizedEqual).toBe(expected)
  })
})
