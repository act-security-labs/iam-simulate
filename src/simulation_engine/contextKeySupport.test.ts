import { describe, expect, it } from 'vitest'
import type { Simulation } from './simulation.js'
import { normalizeSimulationParameters } from './simulationEngine.js'

/** Creates a simulation for testing request context key support. */
function simulationFor(
  action: string,
  resource: string,
  contextVariables: Record<string, string | string[]>
): Simulation {
  return {
    identityPolicies: [],
    serviceControlPolicies: [],
    resourceControlPolicies: [],
    request: {
      action,
      resource: { resource, accountId: '123456789012' },
      principal: 'arn:aws:iam::123456789012:user/Alice',
      contextVariables
    }
  }
}

describe('request context key support', () => {
  it.each([true, false, undefined])(
    'uses the same S3 tag decision when ABAC is %s',
    async (enabled) => {
      //Given an S3 request with a supplied resource tag
      const key = 'aws:ResourceTag/team'
      const simulation = simulationFor('s3:GetObject', 'arn:aws:s3:::example-bucket/object', {
        [key]: 'blue'
      })
      if (enabled !== undefined) {
        simulation.additionalSettings = { s3: { bucketAbacEnabled: enabled } }
      }

      //When normalizing the request and checking Discovery support
      const result = await normalizeSimulationParameters(simulation, undefined)

      //Then the supplied value and absent-key decision agree
      expect(result.isUnsupportedContextKey(key)).toBe(enabled !== true)
      expect(result.validContextValues).toEqual(enabled ? { [key]: 'blue' } : {})
      expect(result.ignoredContextKeys).toEqual(enabled ? [] : [key])
    }
  )

  it('accepts OIDC claims for web identity, including provider paths and array claims', async () => {
    //Given OIDC claims supplied to a web identity request
    const sub = 'oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE:sub'
    const amr = 'oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE:amr'
    const simulation = simulationFor(
      'sts:AssumeRoleWithWebIdentity',
      'arn:aws:iam::123456789012:role/example',
      {
        [sub]: 'subject',
        [amr]: ['authenticated', 'provider']
      }
    )

    //When normalizing and checking support
    const result = await normalizeSimulationParameters(simulation, undefined)

    //Then both claims are accepted and neither is considered absent
    expect(result.validContextValues).toEqual({
      [sub]: 'subject',
      [amr]: ['authenticated', 'provider']
    })
    expect(result.ignoredContextKeys).toEqual([])
    expect(result.isUnsupportedContextKey(sub)).toBe(false)
    expect(result.isUnsupportedContextKey(amr)).toBe(false)
  })

  it('does not treat a service namespace as an OIDC provider', async () => {
    //Given a claim-shaped key under an AWS namespace
    const key = 'aws:sub'
    const simulation = simulationFor(
      'sts:AssumeRoleWithWebIdentity',
      'arn:aws:iam::123456789012:role/example',
      { [key]: 'subject' }
    )

    //When normalizing and checking support
    const result = await normalizeSimulationParameters(simulation, undefined)

    //Then the key is ignored and treated as absent
    expect(result.validContextValues).toEqual({})
    expect(result.ignoredContextKeys).toEqual([key])
    expect(result.isUnsupportedContextKey(key)).toBe(true)
  })

  it('rejects OIDC claims for an action that cannot carry them', async () => {
    //Given an OIDC claim supplied to a non-web-identity action
    const key = 'gitlab.com:sub'
    const simulation = simulationFor('kms:GenerateRandom', '*', { [key]: 'subject' })

    //When normalizing and checking support
    const result = await normalizeSimulationParameters(simulation, undefined)

    //Then both filtering and Discovery reject the claim
    expect(result.validContextValues).toEqual({})
    expect(result.ignoredContextKeys).toEqual([key])
    expect(result.isUnsupportedContextKey(key)).toBe(true)
  })
})
