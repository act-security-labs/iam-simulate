import {
  type ConditionKey,
  findConditionKey,
  getAllGlobalConditionKeys,
  getGlobalConditionKeyByName,
  getGlobalConditionKeyByPrefix,
  iamActionDetails,
  iamActionExists,
  iamConditionKeyDetails,
  iamConditionKeyExists,
  iamConditionKeysForService,
  iamResourceTypeDetails,
  iamServiceExists
} from '@actsecurity/iam-data'
import {
  createValidatedPolicy,
  validateEndpointPolicy,
  validateIdentityPolicy,
  validateResourceControlPolicy,
  validateResourcePolicy,
  validateServiceControlPolicy,
  type ValidationError
} from '@actsecurity/iam-policy'
import { describe, expect, it, vi } from 'vitest'
import { anonymousPrincipal } from '../index.js'
import type { Simulation } from './simulation.js'
import { normalizeSimulationParameters, runSimulation } from './simulationEngine.js'
import type {
  ErrorSimulationResult,
  RunSimulationResults,
  SimulationErrors
} from './simulationEngine.js'

vi.mock('@actsecurity/iam-data')

function assertErrorResult(response: RunSimulationResults): ErrorSimulationResult {
  expect(response.resultType).toEqual('error')
  if (response.resultType !== 'error') {
    throw new Error('Expected error result')
  }
  return response
}

const mockKeyDetails: Record<string, ConditionKey> = {
  's3:requestobjecttagkeys': {
    description: '',
    key: 's3:RequestObjectTagKeys',
    type: 'ArrayOfString'
  },
  's3:resourceaccount': { description: '', key: 's3:ResourceAccount', type: 'String' },
  's3:accessgrantsinstancearn': {
    description: '',
    key: 's3:AccessGrantsInstanceArn',
    type: 'String'
  },
  's3:dataaccesspointaccount': {
    description: '',
    key: 's3:DataAccessPointAccount',
    type: 'String'
  },
  's3:accesspointnetworkorigin': {
    description: '',
    key: 's3:AccessPointNetworkOrigin',
    type: 'String'
  },
  's3:buckettag/${tagkey}': {
    description: '',
    key: 's3:BucketTag/${TagKey}',
    type: 'String'
  }
}

vi.mocked(iamResourceTypeDetails).mockImplementation(async (service, resource) => {
  if (resource === 'object') {
    return {
      arn: 'arn:${Partition}:s3:::${BucketName}/${ObjectName}',
      conditionKeys: [],
      key: 'object'
    }
  } else if (resource === 'bucket') {
    return {
      arn: 'arn:${Partition}:s3:::${BucketName}',
      conditionKeys: [],
      key: 'bucket'
    }
  } else if (resource === 'parameter') {
    return {
      arn: 'arn:${Partition}:ssm:${Region}:${Account}:parameter/${FullyQualifiedParameterName}',
      conditionKeys: [],
      key: 'parameter'
    }
  }
  throw new Error('Resource not found in mock')
})

vi.mocked(iamServiceExists).mockImplementation(async (service) => {
  return ['s3', 'ssm'].includes(service)
})
vi.mocked(iamConditionKeysForService).mockImplementation(async (service) => {
  if (service === 's3') {
    return [
      's3:RequestObjectTagKeys',
      's3:ResourceAccount',
      's3:AccessGrantsInstanceArn',
      's3:DataAccessPointAccount',
      's3:AccessPointNetworkOrigin',
      's3:BucketTag/${TagKey}'
    ]
  }
  return []
})

vi.mocked(iamConditionKeyDetails).mockImplementation(async (service, key) => {
  return mockKeyDetails[key.toLowerCase()]
})

vi.mocked(iamConditionKeyExists).mockImplementation(async (service, key) => {
  return mockKeyDetails[key.toLowerCase()] !== undefined
})

vi.mocked(findConditionKey).mockImplementation(async (key) => {
  const normalizedKey = key.toLowerCase()
  if (mockKeyDetails[normalizedKey]) {
    return mockKeyDetails[normalizedKey]
  }
  if (normalizedKey.startsWith('s3:buckettag/')) {
    return mockKeyDetails['s3:buckettag/${tagkey}']
  }
  return undefined
})

vi.mocked(iamActionExists).mockImplementation(async (service, action) => {
  return (
    (service === 's3' &&
      ['GetObjects', 'GetObject', 'PutObject', 'ListAllMyBuckets', 'ListBucket'].includes(
        action
      )) ||
    (service === 'ssm' && ['GetParameter', 'DescribeParameters'].includes(action))
  )
})

vi.mocked(getAllGlobalConditionKeys).mockImplementation(() => {
  return ['aws:userid', 'aws:username', 'aws:PrincipalOrgPaths', 'aws:RequestTag/tag-key']
})

vi.mocked(getGlobalConditionKeyByPrefix).mockImplementation((key) => {
  if (key.toLowerCase().startsWith('aws:requesttag')) {
    return {
      key: 'aws:RequestTag/tag-key',
      description: '',
      type: 'String',
      category: 'request'
    }
  }
  if (key.toLowerCase().startsWith('aws:resourcetag')) {
    return {
      key: 'aws:ResourceTag/tag-key',
      category: 'resource',
      type: 'String',
      description: ''
    }
  }
  return undefined
})

vi.mocked(getGlobalConditionKeyByName).mockImplementation((key) => {
  if (key.toLowerCase() === 'aws:principalorgpaths') {
    return {
      key: 'aws:PrincipalOrgPaths',
      description: '',
      type: 'ArrayOfString',
      category: 'principal'
    }
  }
  return undefined
})

vi.mocked(iamActionDetails).mockImplementation(async (service, actionKey) => {
  if (actionKey === 'GetObject' || actionKey === 'PutObject') {
    return {
      accessLevel: actionKey === 'GetObject' ? 'Read' : 'Write',
      conditionKeys: ['s3:RequestObjectTagKeys', 's3:ResourceAccount'],
      description: `Grants permission to ${actionKey === 'GetObject' ? 'retrieve' : 'write'} objects in Amazon S3 buckets`,
      name: actionKey,
      resourceTypes: [
        {
          name: 'object',
          required: true,
          dependentActions: [],
          conditionKeys: [
            's3:BucketTag/${TagKey}',
            's3:AccessGrantsInstanceArn',
            's3:DataAccessPointAccount',
            's3:AccessPointNetworkOrigin',
            'aws:ResourceTag/${TagKey}'
          ]
        }
      ],
      dependentActions: [],
      isWildcardOnly: false
    }
  } else if (actionKey === 'ListBucket') {
    return {
      name: 'ListBucket',
      description:
        'Grants permission to list some or all of the objects in an Amazon S3 bucket (up to 1000)',
      accessLevel: 'List',
      resourceTypes: [
        {
          name: 'bucket',
          required: true,
          conditionKeys: [],
          dependentActions: []
        }
      ],
      conditionKeys: [
        's3:AccessGrantsInstanceArn',
        's3:DataAccessPointAccount',
        's3:DataAccessPointArn',
        's3:AccessPointNetworkOrigin',
        's3:authType',
        's3:delimiter',
        's3:max-keys',
        's3:prefix',
        's3:ResourceAccount',
        's3:signatureAge',
        's3:signatureversion',
        's3:TlsVersion',
        's3:x-amz-content-sha256',
        's3:BucketTag/${TagKey}',
        'aws:ResourceTag/${TagKey}'
      ],
      dependentActions: [],
      isWildcardOnly: false
    }
  } else if (actionKey === 'GetObjects') {
    //This is a fake action used in the multiple matching resources test
    return {
      accessLevel: 'Read',
      conditionKeys: ['s3:RequestObjectTagKeys', 's3:ResourceAccount'],
      description: 'Grants permission to retrieve objects from Amazon S3 buckets',
      name: 'GetObject',
      resourceTypes: [
        {
          name: 'object',
          required: true,
          dependentActions: [],
          conditionKeys: [
            's3:AccessGrantsInstanceArn',
            's3:DataAccessPointAccount',
            's3:AccessPointNetworkOrigin',
            'aws:ResourceTag/${TagKey}'
          ]
        },
        {
          name: 'object',
          required: true,
          dependentActions: [],
          conditionKeys: [
            's3:AccessGrantsInstanceArn',
            's3:DataAccessPointAccount',
            's3:AccessPointNetworkOrigin',
            'aws:ResourceTag/${TagKey}'
          ]
        }
      ],
      isWildcardOnly: false,
      dependentActions: []
    }
  } else if (actionKey === 'GetParameter') {
    return {
      name: 'GetParameter',
      description: 'Grants permission to get information about a parameter',
      accessLevel: 'Read',
      resourceTypes: [
        {
          name: 'parameter',
          required: true,
          conditionKeys: [],
          dependentActions: []
        }
      ],
      conditionKeys: [],
      dependentActions: [],
      isWildcardOnly: false
    }
  }
  throw new Error('Action not found in mock')
})

describe('normalizeSimulationParameters', () => {
  it('should only return the parameters allowed for the action', async () => {
    //Given the simulation is for the action s3:GetObject
    const simulation: Simulation = {
      identityPolicies: [],
      serviceControlPolicies: [],
      resourceControlPolicies: [],
      resourcePolicy: undefined,
      request: {
        action: 's3:GetObject',
        resource: {
          resource: 'arn:aws:s3:::examplebucket/1234',
          accountId: '123456789012'
        },
        contextVariables: {
          's3:RequestObjectTagKeys': ['tag1', 'tag2'],
          's3:ResourceAccount': '123456789012',
          's3:DataAccessPointArn': 'arn:aws:s3:us-west-2:123456789012:accesspoint/my-access-point'
        },
        principal: 'arn:aws:iam::123456789012:user/Alice'
      }
    }

    //When we normalize the simulation parameters
    const { validContextValues, ignoredContextKeys } =
      await normalizeSimulationParameters(simulation)

    //Then the result should only contain the parameters allowed for the action
    expect(validContextValues).toEqual({
      's3:RequestObjectTagKeys': ['tag1', 'tag2'],
      's3:ResourceAccount': '123456789012'
    })

    //And the result should contain the ignored context keys
    expect(ignoredContextKeys).toEqual(['s3:DataAccessPointArn'])
  })

  it('should correct incorrect capitalization', async () => {
    //Given the simulation is for the action s3:GetObject
    const simulation: Simulation = {
      identityPolicies: [],
      serviceControlPolicies: [],
      resourceControlPolicies: [],
      resourcePolicy: undefined,
      request: {
        action: 's3:GetObject',
        resource: {
          resource: 'arn:aws:s3:::examplebucket/1234',
          accountId: '123456789012'
        },
        contextVariables: {
          's3:requestobjecttagkeys': ['tag1', 'tag2'],
          's3:rESOURCEaCCOUNT': '123456789012'
        },
        principal: 'arn:aws:iam::123456789012:user/Alice'
      }
    }

    //When we normalize the simulation parameters
    const { validContextValues, ignoredContextKeys } = await normalizeSimulationParameters(
      simulation,
      undefined
    )

    //Then the result correct the capitalization of the keys
    expect(Object.keys(validContextValues).sort()).toEqual([
      's3:RequestObjectTagKeys',
      's3:ResourceAccount'
    ])
    //And the result should contain the ignored context keys
    expect(ignoredContextKeys).toEqual([])
  })

  it('should put single values in an array if the condition key is an array', async () => {
    //Given a request with a single value for request object tag keys
    const simulation: Simulation = {
      identityPolicies: [],
      serviceControlPolicies: [],
      resourceControlPolicies: [],
      resourcePolicy: undefined,
      request: {
        action: 's3:GetObject',
        resource: {
          resource: 'arn:aws:s3:::examplebucket/1234',
          accountId: '123456789012'
        },
        contextVariables: {
          's3:RequestObjectTagKeys': 'tag1'
        },
        principal: 'arn:aws:iam::123456789012:user/Alice'
      }
    }

    //When we normalize the simulation parameters
    const { validContextValues, ignoredContextKeys } = await normalizeSimulationParameters(
      simulation,
      undefined
    )

    //Then the result should put the single value in an array
    expect(validContextValues).toEqual({
      's3:RequestObjectTagKeys': ['tag1']
    })

    //And the result should contain the ignored context keys
    expect(ignoredContextKeys).toEqual([])
  })

  it('should pull the first value from an array if the condition key is a single value', async () => {
    //Given a request with an array value for resource account
    const simulation: Simulation = {
      identityPolicies: [],
      serviceControlPolicies: [],
      resourceControlPolicies: [],
      resourcePolicy: undefined,
      request: {
        action: 's3:GetObject',
        resource: {
          resource: 'arn:aws:s3:::examplebucket/1234',
          accountId: '123456789012'
        },
        contextVariables: {
          's3:ResourceAccount': ['123456789012', '987654321098']
        },
        principal: 'arn:aws:iam::123456789012:user/Alice'
      }
    }

    //When we normalize the simulation parameters
    const { validContextValues, ignoredContextKeys } = await normalizeSimulationParameters(
      simulation,
      undefined
    )

    //Then the result should only contain the first value
    expect(validContextValues).toEqual({
      's3:ResourceAccount': '123456789012'
    })

    //And the result should contain the ignored context keys
    expect(ignoredContextKeys).toEqual([])
  })

  it('should return context keys with variables in them', async () => {
    //Given a request with a variable context key
    const simulation: Simulation = {
      identityPolicies: [],
      serviceControlPolicies: [],
      resourceControlPolicies: [],
      resourcePolicy: undefined,
      request: {
        action: 's3:GetObject',
        resource: {
          resource: 'arn:aws:s3:::examplebucket/1234',
          accountId: '123456789012'
        },
        contextVariables: {
          'aws:RequestTag/Boom': 'Town',
          'aws:AccountTags/Bad': 'News'
        },
        principal: 'arn:aws:iam::123456789012:user/Alice'
      }
    }

    //When we normalize the simulation parameters
    const { validContextValues, ignoredContextKeys } = await normalizeSimulationParameters(
      simulation,
      undefined
    )

    //Then the result should put the single value in an array
    expect(validContextValues).toEqual({
      'aws:RequestTag/Boom': 'Town'
    })

    //And the result should contain the ignored context keys
    expect(ignoredContextKeys).toEqual(['aws:AccountTags/Bad'])
  })
})

describe('runSimulation', () => {
  interface PolicyErrorCase {
    name: string
    badPolicy: any
    validator: (policy: any) => ValidationError[]
    buildSimulation: (policy: any) => Simulation
    getErrors: (errors: SimulationErrors) => ValidationError[] | undefined
    expectedErrors: ValidationError[]
  }

  const userRequest = {
    action: 's3:GetObject',
    resource: {
      resource: 'arn:aws:s3:::examplebucket/1234',
      accountId: '123456789012'
    },
    principal: 'arn:aws:iam::123456789012:user/Alice',
    contextVariables: {}
  }

  const invalidEffectError: ValidationError = {
    path: 'Statement.Effect',
    message: 'Effect must be present and exactly "Allow" or "Deny"'
  }

  const policyErrorCases: PolicyErrorCase[] = [
    {
      name: 'service control policy',
      badPolicy: {
        Statement: {
          Effect: 'SHALL NOT PASS',
          Action: 's3:GetObject',
          Resource: 'arn:aws:s3:::examplebucket/1234'
        }
      },
      validator: validateServiceControlPolicy,
      buildSimulation: (policy) => ({
        identityPolicies: [],
        serviceControlPolicies: [
          {
            orgIdentifier: 'o-123456',
            policies: [{ name: 'Gandalf', policy }]
          }
        ],
        resourceControlPolicies: [],
        resourcePolicy: undefined,
        request: userRequest
      }),
      getErrors: (errors) => errors.serviceControlPolicyErrors?.['Gandalf'],
      expectedErrors: [invalidEffectError]
    },
    {
      name: 'resource policy',
      badPolicy: {
        Statement: {
          Effect: 'Invisible',
          Action: 'oneRing:PutOn',
          NotPrincipal: 'Sauron',
          Resource: 'arn:aws:s3:::ring/theone'
        }
      },
      validator: validateResourcePolicy,
      buildSimulation: (policy) => ({
        identityPolicies: [],
        serviceControlPolicies: [],
        resourceControlPolicies: [],
        resourcePolicy: policy,
        request: userRequest
      }),
      getErrors: (errors) => errors.resourcePolicyErrors,
      expectedErrors: [invalidEffectError]
    },
    {
      name: 'session policy',
      badPolicy: {
        Statement: {
          Effect: 'Domination',
          Action: 'oneRing:PutOn',
          Resource: 'arn:aws:s3:::ring/theone'
        }
      },
      validator: validateIdentityPolicy,
      buildSimulation: (policy) => ({
        identityPolicies: [],
        serviceControlPolicies: [],
        resourceControlPolicies: [],
        resourcePolicy: undefined,
        sessionPolicy: policy,
        request: { ...userRequest, principal: 'arn:aws:iam::123456789012:role/Alice' }
      }),
      getErrors: (errors) => errors.sessionPolicyErrors,
      expectedErrors: [invalidEffectError]
    },
    {
      name: 'identity policy',
      badPolicy: {
        Statement: {
          Effect: 'Domination',
          Action: 'oneRing:PutOn',
          Resource: 'arn:aws:s3:::ring/theone'
        }
      },
      validator: validateIdentityPolicy,
      buildSimulation: (policy) => ({
        identityPolicies: [{ name: 'sauron', policy }],
        serviceControlPolicies: [],
        resourceControlPolicies: [],
        resourcePolicy: undefined,
        request: userRequest
      }),
      getErrors: (errors) => errors.identityPolicyErrors?.['sauron'],
      expectedErrors: [invalidEffectError]
    },
    {
      name: 'resource control policy',
      badPolicy: {
        Version: '2012-10-17',
        Statement: {
          Effect: 'SHALL NOT PASS',
          Action: 's3:GetObject',
          Resource: 'arn:aws:s3:::examplebucket/1234',
          Principal: '*'
        }
      },
      validator: validateResourceControlPolicy,
      buildSimulation: (policy) => ({
        identityPolicies: [],
        serviceControlPolicies: [],
        resourceControlPolicies: [
          {
            orgIdentifier: 'o-123456',
            policies: [{ name: 'Gandalf', policy }]
          }
        ],
        resourcePolicy: undefined,
        request: userRequest
      }),
      getErrors: (errors) => errors.resourceControlPolicyErrors?.['Gandalf'],
      expectedErrors: [
        invalidEffectError,
        {
          path: 'Statement.Effect',
          message: 'Effect must be "Deny" in a resource control policy'
        }
      ]
    },
    {
      name: 'permission boundary',
      badPolicy: { Statement: { Effect: 'Enable', Action: '*', Resource: '*' } },
      validator: validateIdentityPolicy,
      buildSimulation: (policy) => ({
        identityPolicies: [],
        serviceControlPolicies: [],
        resourceControlPolicies: [],
        resourcePolicy: undefined,
        permissionBoundaryPolicies: [{ name: 'permissionBoundary', policy }],
        request: userRequest
      }),
      getErrors: (errors) => errors.permissionBoundaryErrors?.['permissionBoundary'],
      expectedErrors: [invalidEffectError]
    },
    {
      name: 'VPC endpoint policy',
      badPolicy: {
        Statement: {
          Effect: 'Allow',
          Action: 's3:GetObject',
          Resource: 'arn:aws:s3:::examplebucket/1234'
        }
      },
      validator: validateEndpointPolicy,
      buildSimulation: (policy) => ({
        identityPolicies: [],
        serviceControlPolicies: [],
        resourceControlPolicies: [],
        resourcePolicy: undefined,
        vpcEndpointPolicies: [{ name: 'badPolicy', policy }],
        request: userRequest
      }),
      getErrors: (errors) => errors.vpcEndpointErrors?.['badPolicy'],
      expectedErrors: [
        { path: 'Statement', message: 'Principal is required in an endpoint policy' }
      ]
    }
  ]

  const policyForms: Array<{
    label: string
    wrap: (policy: any, validator: (p: any) => ValidationError[]) => any
  }> = [
    { label: 'a raw policy document', wrap: (policy) => policy },
    {
      label: 'a ValidatedPolicy',
      wrap: (policy, validator) => createValidatedPolicy(policy, validator)
    }
  ]

  for (const form of policyForms) {
    describe(`when the invalid policy is ${form.label}`, () => {
      for (const test of policyErrorCases) {
        it(`should return ${test.name} errors`, async () => {
          //Given a simulation with an invalid policy in the ${test.name} slot
          const simulation = test.buildSimulation(form.wrap(test.badPolicy, test.validator))

          //When the simulation is run
          const response = await runSimulation(simulation, {})

          //Then the result should contain the expected validation errors
          const errorResponse = assertErrorResult(response)
          expect(errorResponse.errors.message).toEqual('policy.errors')
          expect(test.getErrors(errorResponse.errors)).toEqual(test.expectedErrors)
        })
      }
    })
  }

  it('should return an error for a mal formatted action', async () => {
    //Given a simulation with a mal formatted action
    const simulation: Simulation = {
      identityPolicies: [],
      serviceControlPolicies: [],
      resourceControlPolicies: [],
      resourcePolicy: undefined,
      request: {
        action: 'oneRing:PutOn:finger',
        resource: {
          resource: 'arn:aws:s3:::examplebucket/1234',
          accountId: '123456789012'
        },
        principal: 'arn:aws:iam::123456789012:user/Alice',
        contextVariables: {}
      }
    }

    //When the simulation is run
    const response = await runSimulation(simulation, {})

    //Then the result should contain an error
    const errorResponse = assertErrorResult(response)
    expect(errorResponse.errors!.message).toEqual('invalid.action')
  })

  it('should return an error for a non existent service', async () => {
    //Given a simulation with a non existent service
    const simulation: Simulation = {
      identityPolicies: [],
      serviceControlPolicies: [],
      resourceControlPolicies: [],
      resourcePolicy: undefined,
      request: {
        action: 'hobbit:EatBreakfast',
        resource: {
          resource: 'arn:aws:s3:::examplebucket/1234',
          accountId: '123456789012'
        },
        principal: 'arn:aws:iam::123456789012:user/Alice',
        contextVariables: {}
      }
    }

    //When the simulation is run
    const response = await runSimulation(simulation, {})

    //Then the result should contain an error
    const errorResponse = assertErrorResult(response)
    expect(errorResponse.errors!.message).toEqual('invalid.service')
  })

  it('should return an error for a non existent action', async () => {
    //Given a simulation with a non existent action
    const simulation: Simulation = {
      identityPolicies: [],
      serviceControlPolicies: [],
      resourceControlPolicies: [],
      resourcePolicy: undefined,
      request: {
        action: 's3:SaveMoneyOnEgress',
        resource: {
          resource: 'arn:aws:s3:::examplebucket/1234',
          accountId: '123456789012'
        },
        principal: 'arn:aws:iam::123456789012:user/Alice',
        contextVariables: {}
      }
    }

    //When the simulation is run
    const response = await runSimulation(simulation, {})

    //Then the result should contain an error
    const errorResponse = assertErrorResult(response)
    expect(errorResponse.errors!.message).toEqual('invalid.action')
  })

  it('should return an error if a wildcard only action is not a wildcard', async () => {
    //Given a request for a wildcard only action with a specific request listed
    const simulation: Simulation = {
      identityPolicies: [],
      serviceControlPolicies: [],
      resourceControlPolicies: [],
      resourcePolicy: undefined,
      request: {
        action: 's3:ListAllMyBuckets',
        resource: {
          resource: 'arn:aws:s3:::examplebucket/1234',
          accountId: '123456789012'
        },
        principal: 'arn:aws:iam::123456789012:user/Alice',
        contextVariables: {}
      }
    }

    vi.mocked(iamActionDetails).mockResolvedValueOnce({
      accessLevel: 'List',
      conditionKeys: [],
      description: 'Grants permission to list all S3 buckets',
      name: 'ListAllMyBuckets',
      resourceTypes: [],
      dependentActions: [],
      isWildcardOnly: true
    })

    //When the simulation is run
    const response = await runSimulation(simulation, {})

    //Then the result should contain an error
    const errorResponse = assertErrorResult(response)
    expect(errorResponse.errors!.message).toEqual('must.use.wildcard')
  })

  it('should return an error if the resource does not mantch an resource type', async () => {
    //Given a request with a resource that does not match any resource types
    const simulation: Simulation = {
      identityPolicies: [],
      serviceControlPolicies: [],
      resourceControlPolicies: [],
      resourcePolicy: undefined,
      request: {
        action: 's3:GetObject',
        resource: {
          resource: 'arn:aws:s3:::examplebucket',
          accountId: '123456789012'
        },
        principal: 'arn:aws:iam::123456789012:user/Alice',
        contextVariables: {}
      }
    }

    //When the simulation is run
    const response = await runSimulation(simulation, {})

    //Then the result should contain an error
    const errorResponse = assertErrorResult(response)
    expect(errorResponse.errors!.message).toEqual('no.resource.types')
  })

  it('should return an error if the resource matches multiple resource types', async () => {
    //Given a request with a resource that matches multiple resource types
    const simulation: Simulation = {
      identityPolicies: [],
      serviceControlPolicies: [],
      resourceControlPolicies: [],
      resourcePolicy: undefined,
      request: {
        action: 's3:GetObjects',
        resource: {
          resource: 'arn:aws:s3:::examplebucket/1234',
          accountId: '123456789012'
        },
        principal: 'arn:aws:iam::123456789012:user/Alice',
        contextVariables: {}
      }
    }

    //When the simulation is run
    const response = await runSimulation(simulation, {})

    //Then the result should contain an error
    const errorResponse = assertErrorResult(response)
    expect(errorResponse.errors!.message).toEqual('multiple.resource.types')
  })

  it('should run a valid simulation', async () => {
    //Given a valid simulation
    const simulation: Simulation = {
      identityPolicies: [
        {
          name: 'readbuckets',
          policy: {
            Statement: {
              Effect: 'Allow',
              Action: 's3:GetObject',
              Resource: 'arn:aws:s3:::examplebucket/*'
            }
          }
        }
      ],
      serviceControlPolicies: [
        {
          orgIdentifier: 'ou-123456',
          policies: [
            {
              name: 'allowall',
              policy: {
                Statement: {
                  Effect: 'Allow',
                  Action: '*',
                  Resource: '*'
                }
              }
            }
          ]
        }
      ],
      resourceControlPolicies: [
        {
          orgIdentifier: 'ou-123456',
          policies: []
        },
        {
          orgIdentifier: 'ou-123456',
          policies: [
            {
              name: 'NoEc2',
              policy: {
                Version: '2012-10-17',
                Statement: {
                  Effect: 'Deny',
                  Action: 'ec2:*',
                  Resource: '*',
                  Principal: '*'
                }
              }
            }
          ]
        }
      ],
      resourcePolicy: {
        Statement: {
          Effect: 'Allow',
          Action: 's3:GetObject',
          Resource: 'arn:aws:s3:::examplebucket/*',
          Principal: 'arn:aws:iam::123456789012:user/Alice'
        }
      },
      permissionBoundaryPolicies: [
        {
          name: 'theBoundary',
          policy: {
            Statement: {
              Effect: 'Allow',
              Action: '*',
              Resource: '*'
            }
          }
        }
      ],
      request: {
        action: 's3:GetObject',
        resource: {
          resource: 'arn:aws:s3:::examplebucket/1234',
          accountId: '123456789012'
        },
        principal: 'arn:aws:iam::123456789012:user/Alice',
        contextVariables: {
          's3:RequestObjectTagKeys': ['tag1', 'tag2'],
          's3:ResourceAccount': '123456789012'
        }
      }
    }

    //When the simulation is run
    const response = await runSimulation(simulation, {})
    expect(response.resultType).toEqual('single')
    if (response.resultType !== 'single') {
      throw new Error('Expected single result')
    }
    const result = response.result

    //Then there should be no errors
    expect(result.analysis?.result).toEqual('Allowed')
    expect(result.ignoredContextKeys).toEqual([])
  })

  it('should run a simulation that is implicitly denied by the session policy', async () => {
    //Given a simulation with an identity policy that allows the request
    //but a session policy that does not allow the action
    const simulation: Simulation = {
      identityPolicies: [
        {
          name: 'allowS3',
          policy: {
            Statement: {
              Effect: 'Allow',
              Action: 's3:GetObject',
              Resource: 'arn:aws:s3:::examplebucket/*'
            }
          }
        }
      ],
      serviceControlPolicies: [],
      resourceControlPolicies: [],
      resourcePolicy: undefined,
      sessionPolicy: {
        Statement: {
          Effect: 'Allow',
          Action: 's3:PutObject',
          Resource: '*'
        }
      },
      request: {
        action: 's3:GetObject',
        resource: {
          resource: 'arn:aws:s3:::examplebucket/1234',
          accountId: '123456789012'
        },
        principal: 'arn:aws:iam::123456789012:role/Alice',
        contextVariables: {}
      }
    }

    //When the simulation is run
    const response = await runSimulation(simulation, {})
    expect(response.resultType).toEqual('single')
    if (response.resultType !== 'single') {
      throw new Error('Expected single result')
    }
    const result = response.result

    //Then there should be no errors and the result should be implicitly denied
    expect(result.analysis?.result).toEqual('ImplicitlyDenied')
    expect(result.ignoredContextKeys).toEqual([])
  })

  it('should return an error if a session policy is not allowed for the principal type', async () => {
    //Given the principal types and whether session policies are allowed for them
    // If the principalType value is true, then a session policy is allowed
    // If the principalType value is false, then a session policy is not allowed
    const principalTypes: Record<string, boolean> = {
      'arn:aws:iam::123456789012:user/Alice': false,
      'arn:aws:sts::123456789012:assumed-role/RoleName/SessionName': true,
      'arn:aws:sts::123456789012:federated-user/FederatedName': true,
      'arn:aws:iam::123456789012:role/RoleName': true
    }

    for (const [principal, sessionPolicyAllowed] of Object.entries(principalTypes)) {
      //Given a simulation with a session policy
      const simulation: Simulation = {
        identityPolicies: [
          {
            name: 'allowS3',
            policy: {
              Statement: {
                Effect: 'Allow',
                Action: 's3:GetObject',
                Resource: 'arn:aws:s3:::examplebucket/*'
              }
            }
          }
        ],
        serviceControlPolicies: [],
        resourceControlPolicies: [],
        resourcePolicy: undefined,
        sessionPolicy: {
          Statement: {
            Effect: 'Allow',
            Action: '*',
            Resource: '*'
          }
        },
        request: {
          action: 's3:GetObject',
          resource: {
            resource: 'arn:aws:s3:::examplebucket/1234',
            accountId: '123456789012'
          },
          principal,
          contextVariables: {}
        }
      }

      //When the simulation is run
      const response = await runSimulation(simulation, {})

      //Then the result should match the expected behavior
      if (sessionPolicyAllowed) {
        expect(response.resultType).toEqual('single')
      } else {
        const errorResponse = assertErrorResult(response)
        expect(
          errorResponse.errors?.message,
          `Principal ${principal} should not allow session policies`
        ).toEqual('session.policy.invalid.principal')
      }
    }
  })

  it('should work with ForAnyValue:StringEquals', async () => {
    const simulation: Simulation = {
      identityPolicies: [
        {
          name: 'policy',
          policy: {
            Version: '2012-10-17',
            Statement: [
              {
                Effect: 'Allow',
                Action: 's3:ListBucket',
                Resource: 'arn:aws:s3:::my-bucket',
                Condition: {
                  'ForAnyValue:StringEquals': {
                    'aws:PrincipalOrgPaths': ['ou-12345']
                  }
                }
              }
            ]
          }
        }
      ],
      serviceControlPolicies: [],
      resourceControlPolicies: [],
      request: {
        action: 's3:ListBucket',
        principal: 'arn:aws:iam::123456789012:user/username',
        resource: {
          accountId: '123456789012',
          resource: 'arn:aws:s3:::my-bucket'
        },
        contextVariables: {
          'aws:PrincipalOrgPaths': ['ou-12345']
        }
      }
    }

    const response = await runSimulation(simulation, {})
    expect(response.resultType).toEqual('single')
    if (response.resultType !== 'single') {
      throw new Error('Expected single result')
    }
    const result = response.result

    expect(result.analysis?.result).toEqual('Allowed')
    expect(result.ignoredContextKeys).toEqual([])
  })

  it('should return ignored context keys', async () => {
    //Given a valid simulation
    const simulation: Simulation = {
      identityPolicies: [
        {
          name: 'readbuckets',
          policy: {
            Statement: {
              Effect: 'Allow',
              Action: 's3:GetObject',
              Resource: 'arn:aws:s3:::examplebucket/*'
            }
          }
        }
      ],
      serviceControlPolicies: [
        {
          orgIdentifier: 'ou-123456',
          policies: [
            {
              name: 'allowall',
              policy: {
                Statement: {
                  Effect: 'Allow',
                  Action: '*',
                  Resource: '*'
                }
              }
            }
          ]
        }
      ],
      resourceControlPolicies: [],
      resourcePolicy: {
        Statement: {
          Effect: 'Allow',
          Action: 's3:GetObject',
          Resource: 'arn:aws:s3:::examplebucket/*',
          Principal: 'arn:aws:iam::123456789012:user/Alice'
        }
      },
      request: {
        action: 's3:GetObject',
        resource: {
          resource: 'arn:aws:s3:::examplebucket/1234',
          accountId: '123456789012'
        },
        principal: 'arn:aws:iam::123456789012:user/Alice',
        contextVariables: {
          's3:RequestObjectTagKeys': ['tag1', 'tag2'],
          's3:ResourceAccount': '123456789012',
          's3:DataAccessPointArn': 'arn:aws:s3:us-west-2:123456789012:accesspoint/my-access-point'
        }
      }
    }

    //When the simulation is run
    const response = await runSimulation(simulation, {})
    expect(response.resultType).toEqual('single')
    if (response.resultType !== 'single') {
      throw new Error('Expected single result')
    }
    const result = response.result

    //Then there should be no errors
    expect(result.ignoredContextKeys).toEqual(['s3:DataAccessPointArn'])
  })

  it('should pass the simulation mode', async () => {
    //Given a valid simulation with strict keys
    const simulation: Simulation = {
      identityPolicies: [
        {
          name: 'readbuckets',
          policy: {
            Statement: {
              Effect: 'Allow',
              Action: 's3:GetObject',
              Resource: 'arn:aws:s3:::examplebucket/*',
              Condition: {
                StringEquals: {
                  'aws:SourceVpc': 'vpc-12345678'
                }
              }
            }
          }
        }
      ],
      serviceControlPolicies: [],
      resourceControlPolicies: [],
      resourcePolicy: undefined,
      request: {
        action: 's3:GetObject',
        resource: {
          resource: 'arn:aws:s3:::examplebucket/1234',
          accountId: '123456789012'
        },
        principal: 'arn:aws:iam::123456789012:user/Alice',
        contextVariables: {
          's3:RequestObjectTagKeys': ['tag1', 'tag2'],
          's3:ResourceAccount': '123456789012'
        }
      }
    }

    //When the simulation is run with strict keys
    const response = await runSimulation(simulation, {
      simulationMode: 'Discovery'
    })
    expect(response.resultType).toEqual('single')
    if (response.resultType !== 'single') {
      throw new Error('Expected single result')
    }
    const result = response.result

    //Then there should be no errors
    expect(result.analysis?.result).toEqual('Allowed')
    expect(result.ignoredContextKeys).toEqual([])
    expect(result.analysis?.ignoredConditions?.identity?.allow?.length).toEqual(1)
    const ignoredCondition = result.analysis?.ignoredConditions?.identity?.allow?.[0]!
    expect(ignoredCondition.key).toEqual('aws:SourceVpc')
    expect(ignoredCondition.values).toEqual(['vpc-12345678'])
    expect(ignoredCondition.op).toEqual('StringEquals')
  })

  it('should pass the simulation mode with strict keys', async () => {
    //Given a valid simulation with strict keys
    const simulation: Simulation = {
      identityPolicies: [
        {
          name: 'readbuckets',
          policy: {
            Statement: {
              Effect: 'Allow',
              Action: 's3:GetObject',
              Resource: 'arn:aws:s3:::examplebucket/*',
              Condition: {
                StringEquals: {
                  'aws:SourceVpc': 'vpc-12345678'
                }
              }
            }
          }
        }
      ],
      serviceControlPolicies: [],
      resourceControlPolicies: [],
      resourcePolicy: undefined,
      request: {
        action: 's3:GetObject',
        resource: {
          resource: 'arn:aws:s3:::examplebucket/1234',
          accountId: '123456789012'
        },
        principal: 'arn:aws:iam::123456789012:user/Alice',
        contextVariables: {
          's3:RequestObjectTagKeys': ['tag1', 'tag2'],
          's3:ResourceAccount': '123456789012'
        }
      }
    }

    //When the simulation is run with strict keys
    const response = await runSimulation(simulation, {
      simulationMode: 'Discovery',
      discoveryContextKeyConstraints: [
        { keyName: 'aws:SourceVpc', presenceIsKnown: true, valueIsKnown: true }
      ]
    })
    expect(response.resultType).toEqual('single')
    if (response.resultType !== 'single') {
      throw new Error('Expected single result')
    }
    const result = response.result

    //Then there should be no errors
    expect(result.analysis?.result).toEqual('ImplicitlyDenied')
    expect(result.ignoredContextKeys).toEqual([])
    expect(result.analysis?.ignoredConditions?.identity).toBeUndefined()
  })

  it('should ignore s3 ABAC keys if ABAC is not enabled on the bucket', async () => {
    //Given a simulation with S3 ABAC context keys and ABAC disabled
    const simulation: Simulation = {
      identityPolicies: [
        {
          name: 'readbuckets',
          policy: {
            Statement: {
              Effect: 'Allow',
              Action: 's3:GetObject',
              Resource: 'arn:aws:s3:::examplebucket/test.txt'
            }
          }
        }
      ],
      serviceControlPolicies: [],
      resourceControlPolicies: [],
      resourcePolicy: undefined,
      request: {
        action: 's3:GetObject',
        resource: {
          resource: 'arn:aws:s3:::examplebucket/1234',
          accountId: '123456789012'
        },
        principal: 'arn:aws:iam::123456789012:user/Alice',
        contextVariables: {
          's3:RequestObjectTagKeys': ['tag1', 'tag2'],
          's3:ResourceAccount': '123456789012',
          'aws:ResourceTag/Environment': 'production',
          's3:BucketTag/Owner': 'team-a'
        }
      }
    }

    //When the simulation is run
    const response = await runSimulation(simulation, {})
    expect(response.resultType).toEqual('single')
    if (response.resultType !== 'single') {
      throw new Error('Expected single result')
    }
    const result = response.result

    //Then there should be no errors
    //And the S3 ABAC keys should be in the ignored context keys
    expect(result.ignoredContextKeys).toContain('aws:ResourceTag/Environment')
    expect(result.ignoredContextKeys).toContain('s3:BucketTag/Owner')
    //And the non-ABAC keys should not be ignored
    expect(result.ignoredContextKeys).not.toContain('s3:RequestObjectTagKeys')
    expect(result.ignoredContextKeys).not.toContain('s3:ResourceAccount')
  })

  it('should not ignore s3 ABAC keys if ABAC is enabled on the bucket', async () => {
    //Given a simulation with S3 ABAC context keys and ABAC enabled
    const simulation: Simulation = {
      identityPolicies: [
        {
          name: 'readbuckets',
          policy: {
            Statement: {
              Effect: 'Allow',
              Action: 's3:GetObject',
              Resource: 'arn:aws:s3:::examplebucket/test.txt'
            }
          }
        }
      ],
      serviceControlPolicies: [],
      resourceControlPolicies: [],
      resourcePolicy: undefined,
      request: {
        action: 's3:GetObject',
        resource: {
          resource: 'arn:aws:s3:::examplebucket/1234',
          accountId: '123456789012'
        },
        principal: 'arn:aws:iam::123456789012:user/Alice',
        contextVariables: {
          's3:RequestObjectTagKeys': ['tag1', 'tag2'],
          's3:ResourceAccount': '123456789012',
          'aws:ResourceTag/Environment': 'production',
          's3:BucketTag/Owner': 'team-a'
        }
      },
      additionalSettings: {
        s3: {
          bucketAbacEnabled: true
        }
      }
    }

    //When the simulation is run
    const response = await runSimulation(simulation, {})
    expect(response.resultType).toEqual('single')
    if (response.resultType !== 'single') {
      throw new Error('Expected single result')
    }
    const result = response.result

    //Then there should be no errors
    //And the ignored context keys should be empty
    expect(result.ignoredContextKeys).toEqual([])
  })

  it.each([
    {
      name: 'AWSLogs prefix under any bucket',
      action: 's3:GetObject',
      identityResource: 'arn:aws:s3:::*/AWSLogs/*',
      resourcePolicyAction: 's3:GetObject',
      exampleConcreteResource: 'arn:aws:s3:::example-bucket/AWSLogs/test.log'
    },
    {
      name: 'nested AWSLogs prefix under any bucket',
      action: 's3:GetObject',
      identityResource: 'arn:aws:s3:::*/*/AWSLogs/*',
      resourcePolicyAction: 's3:GetObject',
      exampleConcreteResource: 'arn:aws:s3:::example-bucket/prefix/AWSLogs/test.log'
    },
    {
      name: 'lowercase ISO extension under any bucket',
      action: 's3:GetObject',
      identityResource: 'arn:aws:s3:::*/*.iso',
      resourcePolicyAction: 's3:GetObject',
      exampleConcreteResource: 'arn:aws:s3:::example-bucket/image.iso'
    },
    {
      name: 'service-generated prefix under any bucket',
      action: 's3:PutObject',
      identityResource: 'arn:aws:s3:::*/generated-prefix-*',
      resourcePolicyAction: 's3:PutObject',
      exampleConcreteResource: 'arn:aws:s3:::example-bucket/generated-prefix-123'
    }
  ])(
    'should allow a cross-account wildcard request when the identity and resource policy patterns overlap for $name',
    async ({ action, identityResource, resourcePolicyAction, exampleConcreteResource }) => {
      //Given a cross-account S3 object request where the identity and resource policy resource patterns overlap
      const simulation: Simulation = {
        identityPolicies: [
          {
            name: 'identityPolicy',
            policy: {
              Version: '2012-10-17',
              Statement: [
                {
                  Effect: 'Allow',
                  Action: action,
                  Resource: identityResource
                }
              ]
            }
          }
        ],
        serviceControlPolicies: [],
        resourceControlPolicies: [],
        resourcePolicy: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Principal: { AWS: 'arn:aws:iam::111111111111:root' },
              Action: resourcePolicyAction,
              Resource: 'arn:aws:s3:::example-bucket/*'
            }
          ]
        },
        request: {
          action,
          resource: {
            resource: 'arn:aws:s3:::example-bucket/*',
            accountId: '222222222222'
          },
          principal: 'arn:aws:iam::111111111111:role/ExampleRole',
          contextVariables: {}
        }
      }

      const concreteSimulation: Simulation = {
        ...simulation,
        request: {
          ...simulation.request,
          resource: {
            ...simulation.request.resource,
            resource: exampleConcreteResource
          }
        }
      }

      //When the wildcard and concrete simulations are run
      const response = await runSimulation(simulation, {})
      const concreteResponse = await runSimulation(concreteSimulation, {})

      //Then a concrete resource in the intersection should already be allowed
      expect(concreteResponse.resultType).toEqual('single')
      if (concreteResponse.resultType !== 'single') {
        throw new Error('Expected single result')
      }
      expect(concreteResponse.overallResult).toEqual('Allowed')

      //And the overlapping subset should make the wildcard request allowed too
      expect(response.resultType).toEqual('wildcard')
      if (response.resultType !== 'wildcard') {
        throw new Error('Expected wildcard result')
      }
      expect(response.overallResult).toEqual('Allowed')
    }
  )

  it('should keep a cross-account wildcard request denied when identity and resource policy patterns do not overlap', async () => {
    //Given a cross-account S3 object request where identity and resource policy patterns are disjoint
    const simulation: Simulation = {
      identityPolicies: [
        {
          name: 'identityPolicy',
          policy: {
            Version: '2012-10-17',
            Statement: [
              {
                Effect: 'Allow',
                Action: 's3:GetObject',
                Resource: 'arn:aws:s3:::other-bucket/*'
              }
            ]
          }
        }
      ],
      serviceControlPolicies: [],
      resourceControlPolicies: [],
      resourcePolicy: {
        Version: '2012-10-17',
        Statement: [
          {
            Effect: 'Allow',
            Principal: { AWS: 'arn:aws:iam::111111111111:root' },
            Action: 's3:GetObject',
            Resource: 'arn:aws:s3:::example-bucket/*'
          }
        ]
      },
      request: {
        action: 's3:GetObject',
        resource: {
          resource: 'arn:aws:s3:::example-bucket/*',
          accountId: '222222222222'
        },
        principal: 'arn:aws:iam::111111111111:role/ExampleRole',
        contextVariables: {}
      }
    }

    //When the wildcard simulation is run
    const response = await runSimulation(simulation, {})

    //Then no synthesized candidate should make the disjoint request allowed
    expect(response.resultType).toEqual('wildcard')
    if (response.resultType !== 'wildcard') {
      throw new Error('Expected wildcard result')
    }
    expect(response.overallResult).toEqual('ImplicitlyDenied')
  })

  describe('anonymous requests', () => {
    const anonymousPublicSimulation = (): Simulation => ({
      identityPolicies: [],
      serviceControlPolicies: [],
      resourceControlPolicies: [],
      resourcePolicy: {
        Version: '2012-10-17',
        Statement: [
          {
            Effect: 'Allow',
            Principal: '*',
            Action: 's3:GetObject',
            Resource: 'arn:aws:s3:::examplebucket/*'
          }
        ]
      },
      request: {
        action: 's3:GetObject',
        resource: {
          resource: 'arn:aws:s3:::examplebucket/1234',
          accountId: '123456789012'
        },
        principal: { type: 'Anonymous' },
        contextVariables: {}
      }
    })

    it('allows an anonymous request with a public resource policy and no RCP', async () => {
      //Given an anonymous request with a public resource policy
      const simulation = anonymousPublicSimulation()

      //When the simulation is run
      const response = await runSimulation(simulation, {})

      //Then the request is allowed
      expect(response.resultType).toEqual('single')
      if (response.resultType !== 'single') {
        throw new Error('Expected single result')
      }
      expect(response.overallResult).toEqual('Allowed')
      expect(response.result.analysis.sameAccount).toEqual(false)
    })

    it('allows an anonymous request using the exported anonymousPrincipal constant', async () => {
      //Given an anonymous request using the exported convenience constant
      const simulation = anonymousPublicSimulation()
      simulation.request.principal = anonymousPrincipal

      //When the simulation is run
      const response = await runSimulation(simulation, {})

      //Then the request is allowed
      expect(response.resultType).toEqual('single')
      if (response.resultType !== 'single') {
        throw new Error('Expected single result')
      }
      expect(response.overallResult).toEqual('Allowed')
    })

    it('blocks an anonymous S3 request when block public access is enabled', async () => {
      //Given an anonymous request with a public bucket policy and S3 BPA enabled
      const simulation = anonymousPublicSimulation()
      simulation.additionalSettings = {
        s3: {
          blockPublicAccess: true
        }
      }

      //When the simulation is run
      const response = await runSimulation(simulation, {})

      //Then the request is blocked by S3 BPA
      expect(response.resultType).toEqual('single')
      if (response.resultType !== 'single') {
        throw new Error('Expected single result')
      }
      expect(response.overallResult).toEqual('ExplicitlyDenied')
      expect(response.result.analysis.blockedBy).toEqual(['s3-bpa'])
    })

    it('does not include resource policy in blockedBy for anonymous resource-policy explicit deny', async () => {
      //Given an anonymous request with a resource-policy explicit deny
      const simulation = anonymousPublicSimulation()
      simulation.resourcePolicy = {
        Version: '2012-10-17',
        Statement: [
          {
            Effect: 'Deny',
            Principal: '*',
            Action: 's3:GetObject',
            Resource: 'arn:aws:s3:::examplebucket/*'
          }
        ]
      }

      //When the simulation is run
      const response = await runSimulation(simulation, {})

      //Then the resource policy is the core decision, not a blockedBy guardrail
      expect(response.resultType).toEqual('single')
      if (response.resultType !== 'single') {
        throw new Error('Expected single result')
      }
      expect(response.overallResult).toEqual('ExplicitlyDenied')
      expect(response.result.analysis.blockedBy).toBeUndefined()
    })

    it('implicitly denies an anonymous request without a resource policy', async () => {
      //Given an anonymous request without a resource policy
      const simulation = anonymousPublicSimulation()
      simulation.resourcePolicy = undefined

      //When the simulation is run
      const response = await runSimulation(simulation, {})

      //Then the request is implicitly denied
      expect(response.resultType).toEqual('single')
      if (response.resultType !== 'single') {
        throw new Error('Expected single result')
      }
      expect(response.overallResult).toEqual('ImplicitlyDenied')
    })

    it('rejects anonymous requests with a session policy', async () => {
      //Given an anonymous request with a session policy
      const simulation = anonymousPublicSimulation()
      simulation.sessionPolicy = { Statement: [{ Effect: 'Allow', Action: '*', Resource: '*' }] }

      //When the simulation is run
      const response = await runSimulation(simulation, {})

      //Then the request is rejected before authorization
      const errorResponse = assertErrorResult(response)
      expect(errorResponse.errors.message).toEqual('anonymous.sessionPolicy.invalid')
      expect(errorResponse.errors.anonymousRequestErrors).toEqual([
        'anonymous.sessionPolicy.invalid'
      ])
    })

    it('rejects anonymous requests with identity policies', async () => {
      //Given an anonymous request with an identity policy
      const simulation = anonymousPublicSimulation()
      simulation.identityPolicies = [
        {
          name: 'IdentityPolicy',
          policy: { Statement: [{ Effect: 'Allow', Action: '*', Resource: '*' }] }
        }
      ]

      //When the simulation is run
      const response = await runSimulation(simulation, {})

      //Then the request is rejected before authorization
      const errorResponse = assertErrorResult(response)
      expect(errorResponse.errors.message).toEqual('anonymous.identityPolicies.invalid')
    })

    it('rejects anonymous requests with permission boundaries', async () => {
      //Given an anonymous request with a permission boundary
      const simulation = anonymousPublicSimulation()
      simulation.permissionBoundaryPolicies = [
        {
          name: 'Boundary',
          policy: { Statement: [{ Effect: 'Allow', Action: '*', Resource: '*' }] }
        }
      ]

      //When the simulation is run
      const response = await runSimulation(simulation, {})

      //Then the request is rejected before authorization
      const errorResponse = assertErrorResult(response)
      expect(errorResponse.errors.message).toEqual('anonymous.permissionBoundaryPolicies.invalid')
    })

    it('rejects anonymous requests with service control policies', async () => {
      //Given an anonymous request with an SCP
      const simulation = anonymousPublicSimulation()
      simulation.serviceControlPolicies = [
        {
          orgIdentifier: 'o-123',
          policies: [
            { name: 'Scp', policy: { Statement: [{ Effect: 'Deny', Action: '*', Resource: '*' }] } }
          ]
        }
      ]

      //When the simulation is run
      const response = await runSimulation(simulation, {})

      //Then the request is rejected before authorization
      const errorResponse = assertErrorResult(response)
      expect(errorResponse.errors.message).toEqual('anonymous.serviceControlPolicies.invalid')
    })

    it('rejects malformed object principals', async () => {
      //Given a malformed object principal
      const simulation = anonymousPublicSimulation()
      simulation.request.principal = { type: 'User' } as any

      //When the simulation is run
      const response = await runSimulation(simulation, {})

      //Then the request is rejected before authorization
      const errorResponse = assertErrorResult(response)
      expect(errorResponse.errors.message).toEqual('invalid.principal')
    })

    it('rejects anonymous principals with extra fields', async () => {
      //Given an anonymous object principal with unsupported fields
      const simulation = anonymousPublicSimulation()
      simulation.request.principal = { type: 'Anonymous', accountId: '123456789012' } as any

      //When the simulation is run
      const response = await runSimulation(simulation, {})

      //Then the request is rejected before authorization
      const errorResponse = assertErrorResult(response)
      expect(errorResponse.errors.message).toEqual('invalid.principal')
    })
  })

  it('should return not allowed without erroring when an identity policy has a CloudFormation Sub resource string', async () => {
    //Given an identity policy with a CloudFormation Sub-style resource string (not a standard ARN)
    const simulation: Simulation = {
      identityPolicies: [
        {
          name: 'ssmPolicy',
          policy: {
            Statement: {
              Action: ['ssm:Get*', 'ssm:Describe*'],
              Effect: 'Allow',
              Resource: [
                'Sub "arn:aws:ssm:${AWS::Region}:${AWS::AccountId}:parameter"/String/3528394562/*'
              ]
            }
          }
        }
      ],
      serviceControlPolicies: [],
      resourceControlPolicies: [],
      request: {
        action: 'ssm:GetParameter',
        resource: {
          resource: 'arn:aws:ssm:us-east-1:123456789012:parameter/String/3528394562/myParam',
          accountId: '123456789012'
        },
        principal: 'arn:aws:iam::123456789012:user/Alice',
        contextVariables: {}
      }
    }

    //When the simulation is run
    const response = await runSimulation(simulation, {})

    //Then it should not return an error
    expect(response.resultType).not.toEqual('error')
    expect(response.resultType).toEqual('single')
    if (response.resultType !== 'single') {
      throw new Error('Expected single result')
    }

    //And the request should be denied (resource does not match the CloudFormation-style string)
    expect(response.result.analysis?.result).not.toEqual('Allowed')
  })
})
