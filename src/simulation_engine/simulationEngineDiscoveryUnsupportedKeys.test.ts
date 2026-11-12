import { describe, expect, it } from 'vitest'
import type { Simulation } from './simulation.js'
import { runSimulation, type RunSimulationResults } from './simulationEngine.js'
import type { SimulationOptions } from './simulationOptions.js'

const allowAllPolicy = (action: string) => ({
  name: 'allow',
  policy: {
    Statement: { Effect: 'Allow', Action: action, Resource: '*' }
  }
})

function simulationFor(
  action: string,
  resource: string,
  policies: Simulation['identityPolicies']
): Simulation {
  return {
    identityPolicies: policies,
    serviceControlPolicies: [],
    resourceControlPolicies: [],
    resourcePolicy: undefined,
    request: {
      action,
      resource: { resource, accountId: '123456789012' },
      principal: 'arn:aws:iam::123456789012:user/Alice',
      contextVariables: {}
    }
  }
}

async function runSingle(
  simulation: Simulation,
  options: SimulationOptions
): Promise<Extract<RunSimulationResults, { resultType: 'single' }>> {
  const response = await runSimulation(simulation, options)
  if (response.resultType !== 'single') {
    throw new Error(`Expected single result, got ${JSON.stringify(response)}`)
  }
  return response
}

const denyIfKeyAbsent = (action: string, key: string) => ({
  name: 'deny-if-absent',
  policy: {
    Statement: {
      Effect: 'Deny',
      Action: action,
      Resource: '*',
      Condition: { Null: { [key]: 'true' } }
    }
  }
})

describe('Discovery mode with condition keys the action can never carry', () => {
  it('explicitly denies kms:GenerateRandom when a Deny requires kms:ViaService to be absent', async () => {
    //Given an allow plus a Deny on a key that iam-data does not list for the action
    const simulation = simulationFor('kms:GenerateRandom', '*', [
      allowAllPolicy('kms:GenerateRandom'),
      denyIfKeyAbsent('kms:GenerateRandom', 'kms:ViaService')
    ])

    //When the simulation runs in Discovery mode
    const response = await runSingle(simulation, { simulationMode: 'Discovery' })

    //Then the key is known to be absent, so the Deny matches
    expect(response.overallResult).toEqual('ExplicitlyDenied')
  })

  it('explicitly denies s3:ListAllMyBuckets when a Deny requires s3:prefix to be absent', async () => {
    //Given an allow plus a Deny on s3:prefix, which only s3:ListBucket carries
    const simulation = simulationFor('s3:ListAllMyBuckets', '*', [
      allowAllPolicy('s3:ListAllMyBuckets'),
      denyIfKeyAbsent('s3:ListAllMyBuckets', 's3:prefix')
    ])

    //When the simulation runs in Discovery mode
    const response = await runSingle(simulation, { simulationMode: 'Discovery' })

    //Then the key is known to be absent, so the Deny matches
    expect(response.overallResult).toEqual('ExplicitlyDenied')
  })

  it('keeps the Deny conditional for kms:Decrypt, which can carry kms:ViaService', async () => {
    //Given the same Deny on an action that does list the key
    const keyArn = 'arn:aws:kms:us-east-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab'
    const simulation = simulationFor('kms:Decrypt', keyArn, [
      allowAllPolicy('kms:Decrypt'),
      denyIfKeyAbsent('kms:Decrypt', 'kms:ViaService')
    ])
    simulation.resourcePolicy = {
      Statement: {
        Effect: 'Allow',
        Principal: { AWS: 'arn:aws:iam::123456789012:root' },
        Action: 'kms:*',
        Resource: '*'
      }
    }

    //When the simulation runs in Discovery mode without a constraint
    const response = await runSingle(simulation, { simulationMode: 'Discovery' })

    //Then the key's presence is still unknown and the Deny is not a definite explicit deny
    expect(response.overallResult).toEqual('Allowed')
    expect(response.result.analysis?.ignoredConditions?.identity?.deny?.length).toEqual(1)
  })

  it('does not let an Allow conditioned on an unsupported key apply in Discovery mode', async () => {
    //Given an Allow that needs kms:ViaService, which kms:GenerateRandom can never carry
    const simulation = simulationFor('kms:GenerateRandom', '*', [
      {
        name: 'allow-via-s3',
        policy: {
          Statement: {
            Effect: 'Allow',
            Action: 'kms:GenerateRandom',
            Resource: '*',
            Condition: { StringEquals: { 'kms:ViaService': 's3.us-east-1.amazonaws.com' } }
          }
        }
      }
    ])

    //When the simulation runs in Discovery mode
    const response = await runSingle(simulation, { simulationMode: 'Discovery' })

    //Then the key is known absent, so the Allow does not match
    expect(response.overallResult).toEqual('ImplicitlyDenied')
  })

  it('leaves Strict mode unchanged for the kms:GenerateRandom Deny', async () => {
    //Given the same policies as the first test
    const simulation = simulationFor('kms:GenerateRandom', '*', [
      allowAllPolicy('kms:GenerateRandom'),
      denyIfKeyAbsent('kms:GenerateRandom', 'kms:ViaService')
    ])

    //When the simulation runs in Strict mode
    const response = await runSingle(simulation, { simulationMode: 'Strict' })

    //Then the absent key already matches the Deny
    expect(response.overallResult).toEqual('ExplicitlyDenied')
  })
})
