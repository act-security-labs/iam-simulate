import { describe, expect, it } from 'vitest'
import {
  DiscoveryContextKeyConstraints,
  type DiscoveryContextKeyConstraint
} from './discoveryContextKeyConstraints.js'

describe('DiscoveryContextKeyConstraints', () => {
  it('treats unsupported keys as absent without overriding caller constraints', () => {
    //Given a request with unsupported keys and an explicit unknown constraint
    const constraints = new DiscoveryContextKeyConstraints(
      [{ keyName: 'kms:ViaService', presenceIsKnown: false, valueIsKnown: false }],
      () => true
    )

    //When looking up configured and unconfigured keys
    const configured = constraints.constraintFor('kms:ViaService')
    const absent = constraints.constraintFor('kms:Other')

    //Then the caller constraint wins and the other key is known absent
    expect(configured).toEqual({
      presenceIsKnown: false,
      valueIsKnown: false,
      explicitlyConfigured: true
    })
    expect(absent).toEqual({
      presenceIsKnown: true,
      valueIsKnown: true,
      explicitlyConfigured: true
    })
  })

  it('keeps request-specific unsupported key results isolated', () => {
    //Given requests with different supported keys
    const unsupported = new DiscoveryContextKeyConstraints([], () => true)
    const supported = new DiscoveryContextKeyConstraints([], () => false)

    //When both requests resolve the same key
    const absent = unsupported.constraintFor('kms:ViaService')
    const unknown = supported.constraintFor('kms:ViaService')

    //Then each request retains its own cached result
    expect(absent.presenceIsKnown).toBe(true)
    expect(unknown).toEqual({
      presenceIsKnown: false,
      valueIsKnown: false,
      explicitlyConfigured: false
    })
    expect(unsupported.constraintFor('kms:ViaService')).toBe(absent)
  })

  it('should return unconstrained for unknown keys', () => {
    //Given constraints for a different key
    const constraints = new DiscoveryContextKeyConstraints([
      { keyName: 'aws:SourceAccount', presenceIsKnown: true, valueIsKnown: false }
    ])

    //When looking up a different key
    const result = constraints.constraintFor('aws:username')

    //Then the result should not be explicitly configured
    expect(result).toEqual({
      presenceIsKnown: false,
      valueIsKnown: false,
      explicitlyConfigured: false
    })
  })

  it('should match literal keys case-insensitively', () => {
    //Given a literal constraint
    const constraints = new DiscoveryContextKeyConstraints([
      { keyName: 'aws:SourceAccount', presenceIsKnown: true, valueIsKnown: false }
    ])

    //When looking up the key with different casing
    const result = constraints.constraintFor('AWS:sourceaccount')

    //Then the literal constraint should match
    expect(result).toEqual({
      presenceIsKnown: true,
      valueIsKnown: false,
      explicitlyConfigured: true
    })
  })

  it('matches literal constraints across Unicode case variants', () => {
    //Given a known literal context key constraint
    const constraints = new DiscoveryContextKeyConstraints([
      { keyName: 'aws:ResourceTag/σ', presenceIsKnown: true, valueIsKnown: true }
    ])

    //When looking up an equivalent final-sigma key
    const result = constraints.constraintFor('aws:ResourceTag/ς')

    //Then the literal constraint applies
    expect(result).toEqual({
      presenceIsKnown: true,
      valueIsKnown: true,
      explicitlyConfigured: true
    })
  })

  it('does not reuse a regex-only result for another Unicode-equivalent literal key', () => {
    //Given a regex whose JavaScript matching distinguishes dotted and plain i
    const constraints = new DiscoveryContextKeyConstraints([
      { keyName: '/^aws:ResourceTag\\/i$/', presenceIsKnown: true, valueIsKnown: true }
    ])

    //When matching plain i and then dotted capital I
    expect(constraints.constraintFor('aws:ResourceTag/i').explicitlyConfigured).toBe(true)
    expect(constraints.constraintFor('aws:ResourceTag/İ').explicitlyConfigured).toBe(false)
  })

  it('should match prefix regex constraints', () => {
    //Given a prefix-style regex constraint
    const constraints = new DiscoveryContextKeyConstraints([
      { keyName: '/^aws:PrincipalTag\\/.*/', presenceIsKnown: true, valueIsKnown: true }
    ])

    //When looking up a matching tag key
    const result = constraints.constraintFor('aws:PrincipalTag/Department')

    //Then the prefix constraint should match
    expect(result).toEqual({
      presenceIsKnown: true,
      valueIsKnown: true,
      explicitlyConfigured: true
    })
  })

  it('should merge matching constraints with true winning', () => {
    //Given literal and pattern constraints for the same key
    const constraints = new DiscoveryContextKeyConstraints([
      { keyName: '/^aws:Source.*/', presenceIsKnown: true, valueIsKnown: false },
      { keyName: 'aws:SourceAccount', presenceIsKnown: false, valueIsKnown: false }
    ])

    //When looking up the key
    const result = constraints.constraintFor('aws:SourceAccount')

    //Then true values should win across matching constraints
    expect(result).toEqual({
      presenceIsKnown: true,
      valueIsKnown: false,
      explicitlyConfigured: true
    })
  })

  it('should reject value-known constraints when presence is unknown', () => {
    //Given an invalid constraint definition
    const invalidConstraints = [
      { keyName: 'aws:SourceAccount', presenceIsKnown: false, valueIsKnown: true }
    ] as unknown as DiscoveryContextKeyConstraint[]
    const create = () => new DiscoveryContextKeyConstraints(invalidConstraints)

    //Then it should reject the invalid state
    expect(create).toThrow('valueIsKnown requires presenceIsKnown')
  })
})
