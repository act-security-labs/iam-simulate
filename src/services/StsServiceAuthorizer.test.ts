import { assert, describe, expect, it } from 'vitest'
import { getDenialReasons } from '../analysis/analyzeResults.js'
import { type Simulation } from '../simulation_engine/simulation.js'
import { runSimulation } from '../simulation_engine/simulationEngine.js'

const accountId = '123456789012'

function stsPolicy({ name, effect }: { name: string; effect: 'Allow' | 'Deny' }) {
  return {
    name,
    policy: {
      Version: '2012-10-17',
      Statement: [{ Effect: effect, Action: 'sts:*', Resource: '*' }]
    }
  }
}

function getSessionTokenSimulation({
  principal,
  identityEffect
}: {
  principal: string
  identityEffect: 'Allow' | 'Deny'
}): Simulation {
  return {
    request: {
      principal,
      action: 'sts:GetSessionToken',
      resource: { resource: '*', accountId },
      contextVariables: {}
    },
    identityPolicies: [stsPolicy({ name: 'identity', effect: identityEffect })],
    serviceControlPolicies: [
      { orgIdentifier: 'ou-root', policies: [stsPolicy({ name: 'scp', effect: 'Deny' })] }
    ],
    resourceControlPolicies: []
  }
}

describe('sts:GetSessionToken through runSimulation, under an SCP that denies sts:*', () => {
  it('denies an assumed-role session whose identity policy allows sts:*, naming no policy as the reason', async () => {
    const response = await runSimulation(
      getSessionTokenSimulation({
        principal: `arn:aws:sts::${accountId}:assumed-role/test-role/session`,
        identityEffect: 'Allow'
      }),
      {}
    )

    assert(response.resultType === 'single')
    expect(response.overallResult).toBe('ImplicitlyDenied')
    expect(getDenialReasons(response.result.analysis)).toEqual([])
  })

  it('allows an IAM user whose identity policy denies sts:*', async () => {
    const response = await runSimulation(
      getSessionTokenSimulation({
        principal: `arn:aws:iam::${accountId}:user/test-user`,
        identityEffect: 'Deny'
      }),
      {}
    )

    assert(response.resultType === 'single')
    expect(response.overallResult).toBe('Allowed')
  })
})
