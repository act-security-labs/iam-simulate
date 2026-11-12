import { describe, expect, it } from 'vitest'
import {
  DiscoveryContextKeyConstraints,
  type DiscoveryContextKeyConstraint
} from './discoveryContextKeyConstraints.js'

describe('DiscoveryContextKeyConstraints', () => {
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

  describe('withUnsupportedKeysAbsent', () => {
    const constraints = new DiscoveryContextKeyConstraints([
      { keyName: 'aws:SourceAccount', presenceIsKnown: true, valueIsKnown: false }
    ])
    const isAllowedContextKey = (key: string) => key.toLowerCase() !== 'kms:viaservice'

    it('should report keys the request cannot carry as known absent', () => {
      //Given a view that rejects kms:ViaService
      const view = constraints.withUnsupportedKeysAbsent(isAllowedContextKey)

      //When looking up the rejected key
      const result = view.constraintFor('kms:ViaService')

      //Then presence and value are authoritative
      expect(result).toEqual({
        presenceIsKnown: true,
        valueIsKnown: true,
        explicitlyConfigured: true
      })
    })

    it('should resolve configured keys the request can carry as constraintFor does', () => {
      //Given a view over constraints with a configured key
      const view = constraints.withUnsupportedKeysAbsent(isAllowedContextKey)

      //Then the configured key resolves unchanged
      expect(view.constraintFor('aws:SourceAccount')).toEqual(
        constraints.constraintFor('aws:SourceAccount')
      )
      expect(view.constraintFor('aws:SourceAccount')).toEqual({
        presenceIsKnown: true,
        valueIsKnown: false,
        explicitlyConfigured: true
      })
    })

    it('should resolve unconfigured keys the request can carry as constraintFor does', () => {
      //Given a view over constraints without the looked-up key
      const view = constraints.withUnsupportedKeysAbsent(isAllowedContextKey)

      //Then the unconfigured key stays unconstrained
      expect(view.constraintFor('aws:username')).toEqual(constraints.constraintFor('aws:username'))
      expect(view.constraintFor('aws:username')).toEqual({
        presenceIsKnown: false,
        valueIsKnown: false,
        explicitlyConfigured: false
      })
    })
  })
})
