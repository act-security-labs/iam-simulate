import { loadPolicy } from '@actsecurity/iam-policy'
import { describe, expect, it } from 'vitest'
import { DiscoveryContextKeyConstraints } from '../../context_keys/discoveryContextKeyConstraints.js'
import { authorize, type AuthorizationRequest } from '../../core_engine/CoreSimulatorEngine.js'
import {
  anonymousPrincipal,
  type SimulationRequestPrincipal
} from '../../simulation_engine/simulation.js'
import { AwsRequestImpl } from '../../request/request.js'
import { RequestContextImpl } from '../../requestContext.js'
import { isStandardS3BucketResource } from './S3ServiceAuthorizer.js'

interface S3BpaRuntimeTestCase {
  name: string
  principal: SimulationRequestPrincipal
  action?: string
  resource?: string
  resourcePolicy?: object
  identityPolicies?: object[]
  context?: Record<string, string | string[]>
  blockPublicAccess?: boolean
  expected: {
    result: 'Allowed' | 'ExplicitlyDenied' | 'ImplicitlyDenied'
    blockedBy?: string[]
  }
}

const s3BpaRuntimeCases: S3BpaRuntimeTestCase[] = [
  {
    name: 'does not block external access when BPA is missing',
    principal: 'arn:aws:iam::222222222222:role/ExternalRole',
    identityPolicies: [allowIdentityPolicy()],
    resourcePolicy: publicBucketPolicy(),
    expected: { result: 'Allowed' }
  },
  {
    name: 'does not block anonymous access when BPA is explicitly disabled',
    principal: anonymousPrincipal,
    resourcePolicy: publicBucketPolicy(),
    blockPublicAccess: false,
    expected: { result: 'Allowed' }
  },
  {
    name: 'blocks anonymous access through a public bucket policy when BPA is enabled',
    principal: anonymousPrincipal,
    resourcePolicy: publicBucketPolicy(),
    blockPublicAccess: true,
    expected: { result: 'ExplicitlyDenied', blockedBy: ['s3-bpa'] }
  },
  {
    name: 'blocks external signed access through a public bucket policy when BPA is enabled',
    principal: 'arn:aws:iam::222222222222:role/ExternalRole',
    identityPolicies: [allowIdentityPolicy()],
    resourcePolicy: publicBucketPolicy(),
    blockPublicAccess: true,
    expected: { result: 'ExplicitlyDenied', blockedBy: ['s3-bpa'] }
  },
  {
    name: 'blocks external signed access to a bucket ARN when BPA is enabled',
    principal: 'arn:aws:iam::222222222222:role/ExternalRole',
    action: 's3:GetBucketLocation',
    resource: 'arn:aws:s3:::example-bucket',
    identityPolicies: [allowIdentityPolicy('s3:GetBucketLocation', 'arn:aws:s3:::example-bucket')],
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: 's3:GetBucketLocation',
          Resource: 'arn:aws:s3:::example-bucket'
        }
      ]
    },
    blockPublicAccess: true,
    expected: { result: 'ExplicitlyDenied', blockedBy: ['s3-bpa'] }
  },
  {
    name: 'blocks external signed access to an object wildcard ARN when BPA is enabled',
    principal: 'arn:aws:iam::222222222222:role/ExternalRole',
    resource: 'arn:aws:s3:::example-bucket/*',
    identityPolicies: [allowIdentityPolicy()],
    resourcePolicy: publicBucketPolicy(),
    blockPublicAccess: true,
    expected: { result: 'ExplicitlyDenied', blockedBy: ['s3-bpa'] }
  },
  {
    name: 'blocks external signed access to a wildcard bucket object ARN when BPA is enabled',
    principal: 'arn:aws:iam::222222222222:role/ExternalRole',
    resource: 'arn:aws:s3:::*/*',
    identityPolicies: [allowIdentityPolicy('s3:GetObject', 'arn:aws:s3:::*/*')],
    resourcePolicy: publicBucketPolicy(),
    blockPublicAccess: true,
    expected: { result: 'ExplicitlyDenied', blockedBy: ['s3-bpa'] }
  },
  {
    name: 'blocks external signed access to all resources wildcard when BPA is enabled',
    principal: 'arn:aws:iam::222222222222:role/ExternalRole',
    resource: '*',
    identityPolicies: [allowIdentityPolicy('s3:GetObject', '*')],
    resourcePolicy: publicBucketPolicy(),
    blockPublicAccess: true,
    expected: { result: 'ExplicitlyDenied', blockedBy: ['s3-bpa'] }
  },
  {
    name: 'allows same-account access through a public bucket policy when BPA is enabled',
    principal: 'arn:aws:iam::111111111111:role/SameAccountRole',
    resourcePolicy: publicBucketPolicy(),
    blockPublicAccess: true,
    expected: { result: 'Allowed' }
  },
  {
    name: 'does not override same-account explicit resource-policy deny when BPA is enabled',
    principal: 'arn:aws:iam::111111111111:role/SameAccountRole',
    identityPolicies: [allowIdentityPolicy()],
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: 's3:GetObject',
          Resource: 'arn:aws:s3:::example-bucket/*'
        },
        {
          Effect: 'Deny',
          Principal: { AWS: 'arn:aws:iam::111111111111:role/SameAccountRole' },
          Action: 's3:GetObject',
          Resource: 'arn:aws:s3:::example-bucket/*'
        }
      ]
    },
    blockPublicAccess: true,
    expected: { result: 'ExplicitlyDenied', blockedBy: ['resource'] }
  },
  {
    name: 'allows service principal access through a public bucket policy when BPA is enabled',
    principal: 'cloudfront.amazonaws.com',
    resourcePolicy: publicBucketPolicy(),
    blockPublicAccess: true,
    expected: { result: 'Allowed' }
  },
  {
    name: 'allows external role access through a specific non-public bucket policy when BPA is enabled',
    principal: 'arn:aws:iam::222222222222:role/ExternalRole',
    identityPolicies: [allowIdentityPolicy()],
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: { AWS: 'arn:aws:iam::222222222222:role/ExternalRole' },
          Action: 's3:GetObject',
          Resource: 'arn:aws:s3:::example-bucket/*'
        }
      ]
    },
    blockPublicAccess: true,
    expected: { result: 'Allowed' }
  },
  {
    name: 'allows external account root principal access when BPA is enabled',
    principal: 'arn:aws:iam::222222222222:role/ExternalRole',
    identityPolicies: [allowIdentityPolicy()],
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: { AWS: 'arn:aws:iam::222222222222:root' },
          Action: 's3:GetObject',
          Resource: 'arn:aws:s3:::example-bucket/*'
        }
      ]
    },
    blockPublicAccess: true,
    expected: { result: 'Allowed' }
  },
  {
    name: 'blocks external access when unrelated public statement taints the bucket policy',
    principal: 'arn:aws:iam::222222222222:role/ExternalRole',
    identityPolicies: [allowIdentityPolicy()],
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: 's3:GetBucketLocation',
          Resource: 'arn:aws:s3:::example-bucket'
        },
        {
          Effect: 'Allow',
          Principal: { AWS: 'arn:aws:iam::222222222222:role/ExternalRole' },
          Action: 's3:GetObject',
          Resource: 'arn:aws:s3:::example-bucket/*'
        }
      ]
    },
    blockPublicAccess: true,
    expected: { result: 'ExplicitlyDenied', blockedBy: ['s3-bpa'] }
  },
  {
    name: 'allows matching org-constrained wildcard access when BPA is enabled',
    principal: 'arn:aws:iam::222222222222:role/ExternalRole',
    identityPolicies: [allowIdentityPolicy()],
    context: { 'aws:PrincipalOrgID': 'o-8jc0e05m21' },
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: 's3:GetObject',
          Resource: 'arn:aws:s3:::example-bucket/*',
          Condition: { StringEquals: { 'aws:PrincipalOrgID': 'o-8jc0e05m21' } }
        }
      ]
    },
    blockPublicAccess: true,
    expected: { result: 'Allowed' }
  },
  {
    name: 'blocks external access when SecureTransport condition does not make policy non-public',
    principal: 'arn:aws:iam::222222222222:role/ExternalRole',
    identityPolicies: [allowIdentityPolicy()],
    context: { 'aws:SecureTransport': 'true' },
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: 's3:GetObject',
          Resource: 'arn:aws:s3:::example-bucket/*',
          Condition: { Bool: { 'aws:SecureTransport': 'true' } }
        }
      ]
    },
    blockPublicAccess: true,
    expected: { result: 'ExplicitlyDenied', blockedBy: ['s3-bpa'] }
  }
]

describe('isStandardS3BucketResource', () => {
  const resourceCases: Array<{ name: string; resource: string; expected: boolean }> = [
    {
      name: 'standard bucket ARN',
      resource: 'arn:aws:s3:::example-bucket',
      expected: true
    },
    {
      name: 'standard object ARN',
      resource: 'arn:aws:s3:::example-bucket/object.txt',
      expected: true
    },
    {
      name: 'standard object wildcard ARN',
      resource: 'arn:aws:s3:::example-bucket/*',
      expected: true
    },
    {
      name: 'wildcard bucket ARN',
      resource: 'arn:aws:s3:::*',
      expected: true
    },
    {
      name: 'wildcard bucket object ARN',
      resource: 'arn:aws:s3:::*/*',
      expected: true
    },
    {
      name: 'all resources wildcard',
      resource: '*',
      expected: true
    },
    {
      name: 'S3 access point ARN',
      resource: 'arn:aws:s3:us-east-1:111111111111:accesspoint/example/object/test.txt',
      expected: false
    },
    {
      name: 'S3 Express bucket ARN',
      resource: 'arn:aws:s3express:us-east-1:111111111111:bucket/example-bucket',
      expected: false
    },
    {
      name: 'S3 Outposts bucket ARN',
      resource:
        'arn:aws:s3-outposts:us-east-1:111111111111:outpost/op-1234567890abcdef0/bucket/example-bucket',
      expected: false
    },
    {
      name: 'S3 object lambda access point ARN',
      resource: 'arn:aws:s3-object-lambda:us-east-1:111111111111:accesspoint/example',
      expected: false
    },
    {
      name: 'S3 ARN with region is not a standard bucket ARN',
      resource: 'arn:aws:s3:us-east-1::example-bucket',
      expected: false
    },
    {
      name: 'S3 ARN with account is not a standard bucket ARN',
      resource: 'arn:aws:s3::111111111111:example-bucket',
      expected: false
    },
    {
      name: 'empty S3 resource part is not a standard bucket ARN',
      resource: 'arn:aws:s3:::',
      expected: false
    },
    {
      name: 'empty bucket name before object delimiter is not a standard bucket ARN',
      resource: 'arn:aws:s3:::/object.txt',
      expected: false
    },
    {
      name: 'non-S3 ARN is not a standard bucket ARN',
      resource: 'arn:aws:sqs:us-east-1:111111111111:example-queue',
      expected: false
    },
    {
      name: 'malformed resource is not a standard bucket ARN',
      resource: 'example-bucket/object.txt',
      expected: false
    }
  ]

  it.each(resourceCases)('$name', ({ resource, expected }) => {
    expect(isStandardS3BucketResource(resource)).toBe(expected)
  })
})

describe('S3ServiceAuthorizer', () => {
  it.each(s3BpaRuntimeCases)('$name', (testCase) => {
    //Given an S3 authorization request
    const request = authorizationRequest(testCase)

    //When the request is authorized
    const analysis = authorize(request)

    //Then the S3 BPA runtime result should match expectations
    expect(analysis.result).toBe(testCase.expected.result)
    expect(analysis.blockedBy?.sort()).toEqual(testCase.expected.blockedBy?.sort())
  })
})

function authorizationRequest(testCase: S3BpaRuntimeTestCase): AuthorizationRequest {
  return {
    request: new AwsRequestImpl(
      testCase.principal,
      {
        resource: testCase.resource ?? 'arn:aws:s3:::example-bucket/object.txt',
        accountId: '111111111111'
      },
      testCase.action ?? 's3:GetObject',
      new RequestContextImpl(testCase.context ?? {})
    ),
    sessionPolicy: undefined,
    identityPolicies: (testCase.identityPolicies ?? []).map((policy, index) =>
      loadPolicy(policy, { name: `identity-${index}` })
    ),
    serviceControlPolicies: [],
    resourceControlPolicies: [],
    resourcePolicy: testCase.resourcePolicy
      ? loadPolicy(testCase.resourcePolicy, { name: 'ResourcePolicy' })
      : undefined,
    permissionBoundaries: undefined,
    vpcEndpointPolicies: undefined,
    simulationParameters: {
      simulationMode: 'Strict',
      discoveryContextKeyConstraints: new DiscoveryContextKeyConstraints([])
    },
    serviceSettings: {
      s3: {
        blockPublicAccess: testCase.blockPublicAccess
      }
    }
  }
}

function publicBucketPolicy(): object {
  return {
    Version: '2012-10-17',
    Statement: [
      {
        Effect: 'Allow',
        Principal: '*',
        Action: 's3:GetObject',
        Resource: 'arn:aws:s3:::example-bucket/*'
      }
    ]
  }
}

function allowIdentityPolicy(
  action = 's3:GetObject',
  resource = 'arn:aws:s3:::example-bucket/*'
): object {
  return {
    Version: '2012-10-17',
    Statement: [
      {
        Effect: 'Allow',
        Action: action,
        Resource: resource
      }
    ]
  }
}
