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
  it('allows an OAI using only a matching bucket policy', () => {
    //Given an OAI and a matching resource policy without identity policies
    const principal = 'arn:aws:iam::cloudfront:user/CloudFront Origin Access Identity E123'
    const request = authorizationRequest({
      name: 'OAI resource policy',
      principal,
      resourcePolicy: {
        Version: '2012-10-17',
        Statement: [
          { Effect: 'Allow', Principal: { AWS: principal }, Action: 's3:GetObject', Resource: '*' }
        ]
      },
      expected: { result: 'Allowed' }
    })

    //When the request is authorized
    const analysis = authorize(request)

    //Then the OAI uses its resource policy, not a fabricated identity policy
    expect(analysis.result).toBe('Allowed')
    expect(analysis.identityAnalysis.result).toBe('NotApplicable')
  })

  it.each([
    'GetObject',
    'PutObject',
    'DeleteObject',
    'GetObjectAcl',
    'GetObjectAttributes',
    'GetObjectTagging',
    'DeleteObjectTagging',
    'AbortMultipartUpload',
    'ListBucket',
    'GetBucketAcl',
    'GetBucketLocation',
    'GetBucketVersioning',
    'GetBucketPolicyStatus',
    'GetEncryptionConfiguration',
    'GetBucketPublicAccessBlock',
    'ListBucketVersions',
    'ListBucketMultipartUploads'
  ])('allows a resource-policy grant for validated OAI action s3:%s', (action) => {
    const principal = 'arn:aws:iam::cloudfront:user/CloudFront Origin Access Identity E123'
    const request = authorizationRequest({
      name: action,
      principal,
      action: `s3:${action}`,
      resourcePolicy: {
        Version: '2012-10-17',
        Statement: [
          { Effect: 'Allow', Principal: { AWS: principal }, Action: 's3:*', Resource: '*' }
        ]
      },
      expected: { result: 'Allowed' }
    })
    expect(authorize(request).result).toBe('Allowed')
  })

  it('does not apply a CloudFront service NotPrincipal deny to an OAI', () => {
    //Given a separate OAI grant and a deny excluding the CloudFront service principal
    const principal = 'arn:aws:iam::cloudfront:user/CloudFront Origin Access Identity E123'
    const request = authorizationRequest({
      name: 'OAI and CloudFront NotPrincipal',
      principal,
      resourcePolicy: {
        Version: '2012-10-17',
        Statement: [
          { Effect: 'Allow', Principal: { AWS: principal }, Action: 's3:GetObject', Resource: '*' },
          {
            Effect: 'Deny',
            NotPrincipal: { Service: 'cloudfront.amazonaws.com' },
            Action: 's3:GetObject',
            Resource: '*'
          }
        ]
      },
      expected: { result: 'Allowed' }
    })

    //When the request is authorized
    const result = authorize(request)

    //Then the NotPrincipal deny does not apply
    expect(result.result).toBe('Allowed')
    expect(result.resourceAnalysis?.unmatchedStatements[0]?.principalMatch).toBe('NoMatch')
  })

  it('does not treat an OAI as the CloudFront service principal in an Allow', () => {
    const request = authorizationRequest({
      name: 'OAI is not OAC',
      principal: 'arn:aws:iam::cloudfront:user/CloudFront Origin Access Identity E123',
      resourcePolicy: {
        Version: '2012-10-17',
        Statement: [
          {
            Effect: 'Allow',
            Principal: { Service: 'cloudfront.amazonaws.com' },
            Action: 's3:GetObject',
            Resource: '*'
          }
        ]
      },
      expected: { result: 'ImplicitlyDenied' }
    })
    expect(authorize(request).result).toBe('ImplicitlyDenied')
  })

  it('preserves an unknown OAI context value as a Discovery condition', () => {
    const principal = 'arn:aws:iam::cloudfront:user/CloudFront Origin Access Identity E123'
    const request = authorizationRequest({
      name: 'OAI discovery context',
      principal,
      context: { 'aws:PrincipalType': 'placeholder' },
      resourcePolicy: {
        Version: '2012-10-17',
        Statement: [
          {
            Effect: 'Allow',
            Principal: { AWS: principal },
            Action: 's3:GetObject',
            Resource: '*',
            Condition: { StringEquals: { 'aws:PrincipalType': 'User' } }
          }
        ]
      },
      expected: { result: 'Allowed' }
    })
    request.simulationParameters = {
      simulationMode: 'Discovery',
      discoveryContextKeyConstraints: new DiscoveryContextKeyConstraints([
        { keyName: 'aws:PrincipalType', presenceIsKnown: true, valueIsKnown: false }
      ])
    }
    const result = authorize(request)
    expect(result.result).toBe('Allowed')
    expect(result.conditions).toMatchObject({
      conditionType: 'condition',
      key: 'aws:PrincipalType',
      values: ['User']
    })
  })

  it('caps unvalidated OAI actions even if policies allow them', () => {
    const principal = 'arn:aws:iam::cloudfront:user/CloudFront Origin Access Identity E123'
    const request = authorizationRequest({
      name: 'outside product cap',
      principal,
      action: 's3:PutBucketPolicy',
      identityPolicies: [allowIdentityPolicy('s3:*', '*')],
      resourcePolicy: {
        Version: '2012-10-17',
        Statement: [{ Effect: 'Allow', Principal: '*', Action: 's3:*', Resource: '*' }]
      },
      expected: { result: 'ImplicitlyDenied' }
    })
    expect(authorize(request).result).toBe('ImplicitlyDenied')
  })

  it('preserves a matching explicit deny even outside the OAI action cap', () => {
    const principal = 'arn:aws:iam::cloudfront:user/CloudFront Origin Access Identity E123'
    const request = authorizationRequest({
      name: 'explicit deny',
      principal,
      action: 's3:PutBucketPolicy',
      resourcePolicy: {
        Version: '2012-10-17',
        Statement: [{ Effect: 'Deny', Principal: '*', Action: 's3:*', Resource: '*' }]
      },
      expected: { result: 'ExplicitlyDenied' }
    })
    expect(authorize(request).result).toBe('ExplicitlyDenied')
  })

  it('does not allow an OAI to use a non-S3 action, even with supplied identity policies', () => {
    const principal = 'arn:aws:iam::cloudfront:user/CloudFront Origin Access Identity E123'
    const request = authorizationRequest({
      name: 'OAI outside S3',
      principal,
      action: 'sqs:SendMessage',
      resource: 'arn:aws:sqs:us-east-1:111111111111:queue',
      identityPolicies: [allowIdentityPolicy('*', '*')],
      resourcePolicy: {
        Version: '2012-10-17',
        Statement: [{ Effect: 'Allow', Principal: { AWS: principal }, Action: '*', Resource: '*' }]
      },
      expected: { result: 'ImplicitlyDenied' }
    })
    expect(authorize(request)).toEqual({ result: 'ImplicitlyDenied', sameAccount: false })
  })

  it('rejects a non-S3 OAI request before evaluating an explicit policy deny', () => {
    const principal = 'arn:aws:iam::cloudfront:user/CloudFront Origin Access Identity E123'
    const request = authorizationRequest({
      name: 'OAI outside S3 with explicit deny',
      principal,
      action: 'sqs:SendMessage',
      resource: 'arn:aws:sqs:us-east-1:111111111111:queue',
      resourcePolicy: {
        Version: '2012-10-17',
        Statement: [{ Effect: 'Deny', Principal: '*', Action: '*', Resource: '*' }]
      },
      expected: { result: 'ImplicitlyDenied' }
    })
    expect(authorize(request)).toEqual({ result: 'ImplicitlyDenied', sameAccount: false })
  })

  it('still applies a supplied resource control policy deny to OAI access', () => {
    const principal = 'arn:aws:iam::cloudfront:user/CloudFront Origin Access Identity E123'
    const request = authorizationRequest({
      name: 'OAI with resource guardrail',
      principal,
      resourcePolicy: {
        Version: '2012-10-17',
        Statement: [
          { Effect: 'Allow', Principal: { AWS: principal }, Action: 's3:GetObject', Resource: '*' }
        ]
      },
      expected: { result: 'ExplicitlyDenied' }
    })
    request.resourceControlPolicies = [
      {
        orgIdentifier: 'ou-example',
        policies: [
          loadPolicy(
            {
              Version: '2012-10-17',
              Statement: [
                { Effect: 'Allow', Principal: '*', Action: '*', Resource: '*' },
                { Effect: 'Deny', Principal: '*', Action: 's3:GetObject', Resource: '*' }
              ]
            },
            { name: 'rcp' }
          )
        ]
      }
    ]
    const analysis = authorize(request)
    expect(analysis.result).toBe('ExplicitlyDenied')
    expect(analysis.blockedBy).toContain('rcp')
  })

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
