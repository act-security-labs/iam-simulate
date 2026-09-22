import { loadPolicy } from '@actsecurity/iam-policy'
import { describe, expect, it } from 'vitest'
import { classifyS3RuntimePublicBucketPolicy } from './s3BlockPublicAccess.js'

interface RuntimePublicClassifierTestCase {
  name: string
  policy: object
  expected: 'public' | 'nonPublic'
  publicStatements?: Array<{ index: number; sid?: string }>
}

const bucketArn = 'arn:aws:s3:::example-bucket'
const objectArn = `${bucketArn}/*`

const classifierCases: RuntimePublicClassifierTestCase[] = [
  {
    name: 'bare wildcard principal is public',
    policy: allowPolicy({ Sid: 'PublicWildcard', Principal: '*' }),
    expected: 'public',
    publicStatements: [{ index: 1, sid: 'PublicWildcard' }]
  },
  {
    name: 'AWS wildcard principal is public',
    policy: allowPolicy({ Sid: 'AwsWildcard', Principal: { AWS: '*' } }),
    expected: 'public',
    publicStatements: [{ index: 1, sid: 'AwsWildcard' }]
  },
  {
    name: 'public statement without Sid returns only the statement index',
    policy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: 's3:GetObject',
          Resource: objectArn
        }
      ]
    },
    expected: 'public',
    publicStatements: [{ index: 1 }]
  },
  {
    name: 'specific external role principal is non-public',
    policy: allowPolicy({
      Sid: 'SpecificRole',
      Principal: { AWS: 'arn:aws:iam::222222222222:role/ExampleRole' }
    }),
    expected: 'nonPublic'
  },
  {
    name: 'external account root principal is non-public',
    policy: allowPolicy({
      Sid: 'ExternalRoot',
      Principal: { AWS: 'arn:aws:iam::222222222222:root' }
    }),
    expected: 'nonPublic'
  },
  {
    name: 'service principal is non-public',
    policy: allowPolicy({
      Sid: 'CloudFrontService',
      Principal: { Service: 'cloudfront.amazonaws.com' }
    }),
    expected: 'nonPublic'
  },
  {
    name: 'PrincipalArn exact role condition is non-public',
    policy: wildcardAllowWithCondition('PrincipalArnExact', {
      ArnEquals: { 'aws:PrincipalArn': 'arn:aws:iam::111111111111:role/ExampleRole' }
    }),
    expected: 'nonPublic'
  },
  {
    name: 'PrincipalArn wildcard role path in fixed account is non-public',
    policy: wildcardAllowWithCondition('PrincipalArnRoleWildcard', {
      ArnLike: { 'aws:PrincipalArn': 'arn:aws:iam::111111111111:role/*' }
    }),
    expected: 'nonPublic'
  },
  {
    name: 'PrincipalArn wildcard account is public',
    policy: wildcardAllowWithCondition('PrincipalArnWildcardAccount', {
      ArnLike: { 'aws:PrincipalArn': 'arn:aws:iam::*:role/ExampleRole' }
    }),
    expected: 'public',
    publicStatements: [{ index: 1, sid: 'PrincipalArnWildcardAccount' }]
  },
  {
    name: 'PrincipalArn StringEquals condition is non-public',
    policy: wildcardAllowWithCondition('PrincipalArnStringEquals', {
      StringEquals: { 'aws:PrincipalArn': 'arn:aws:iam::111111111111:role/ExampleRole' }
    }),
    expected: 'nonPublic'
  },
  {
    name: 'PrincipalArn StringLike condition is non-public',
    policy: wildcardAllowWithCondition('PrincipalArnStringLike', {
      StringLike: { 'aws:PrincipalArn': 'arn:aws:iam::111111111111:role/ExampleRole' }
    }),
    expected: 'nonPublic'
  },
  {
    name: 'PrincipalArn StringLike with fixed-account resource wildcard is non-public',
    policy: wildcardAllowWithCondition('PrincipalArnStringLikeResourceWildcard', {
      StringLike: { 'aws:PrincipalArn': 'arn:aws:iam::111111111111:role/*' }
    }),
    expected: 'nonPublic'
  },
  {
    name: 'PrincipalArn StringLike with wildcard account is public',
    policy: wildcardAllowWithCondition('PrincipalArnStringLikeWildcardAccount', {
      StringLike: { 'aws:PrincipalArn': 'arn:aws:iam::*:role/ExampleRole' }
    }),
    expected: 'public',
    publicStatements: [{ index: 1, sid: 'PrincipalArnStringLikeWildcardAccount' }]
  },
  {
    name: 'PrincipalArn StringEqualsIgnoreCase condition is non-public',
    policy: wildcardAllowWithCondition('PrincipalArnStringEqualsIgnoreCase', {
      StringEqualsIgnoreCase: {
        'aws:PrincipalArn': 'arn:aws:iam::111111111111:role/ExampleRole'
      }
    }),
    expected: 'nonPublic'
  },
  {
    name: 'PrincipalArn StringNotEquals condition is public',
    policy: wildcardAllowWithCondition('PrincipalArnStringNotEquals', {
      StringNotEquals: { 'aws:PrincipalArn': 'arn:aws:iam::111111111111:role/ExampleRole' }
    }),
    expected: 'public',
    publicStatements: [{ index: 1, sid: 'PrincipalArnStringNotEquals' }]
  },
  {
    name: 'PrincipalArn StringNotLike condition is public',
    policy: wildcardAllowWithCondition('PrincipalArnStringNotLike', {
      StringNotLike: { 'aws:PrincipalArn': 'arn:aws:iam::111111111111:role/ExampleRole' }
    }),
    expected: 'public',
    publicStatements: [{ index: 1, sid: 'PrincipalArnStringNotLike' }]
  },
  {
    name: 'PrincipalArn StringEqualsIfExists condition is public',
    policy: wildcardAllowWithCondition('PrincipalArnStringEqualsIfExists', {
      StringEqualsIfExists: {
        'aws:PrincipalArn': 'arn:aws:iam::111111111111:role/ExampleRole'
      }
    }),
    expected: 'public',
    publicStatements: [{ index: 1, sid: 'PrincipalArnStringEqualsIfExists' }]
  },
  {
    name: 'PrincipalArn StringLikeIfExists condition is public',
    policy: wildcardAllowWithCondition('PrincipalArnStringLikeIfExists', {
      StringLikeIfExists: { 'aws:PrincipalArn': 'arn:aws:iam::111111111111:role/ExampleRole' }
    }),
    expected: 'public',
    publicStatements: [{ index: 1, sid: 'PrincipalArnStringLikeIfExists' }]
  },
  {
    name: 'PrincipalArn StringEqualsIgnoreCaseIfExists condition is public',
    policy: wildcardAllowWithCondition('PrincipalArnStringEqualsIgnoreCaseIfExists', {
      StringEqualsIgnoreCaseIfExists: {
        'aws:PrincipalArn': 'arn:aws:iam::111111111111:role/ExampleRole'
      }
    }),
    expected: 'public',
    publicStatements: [{ index: 1, sid: 'PrincipalArnStringEqualsIgnoreCaseIfExists' }]
  },
  {
    name: 'PrincipalArn StringNotEqualsIfExists condition is public',
    policy: wildcardAllowWithCondition('PrincipalArnStringNotEqualsIfExists', {
      StringNotEqualsIfExists: {
        'aws:PrincipalArn': 'arn:aws:iam::111111111111:role/ExampleRole'
      }
    }),
    expected: 'public',
    publicStatements: [{ index: 1, sid: 'PrincipalArnStringNotEqualsIfExists' }]
  },
  {
    name: 'PrincipalArn StringNotLikeIfExists condition is public',
    policy: wildcardAllowWithCondition('PrincipalArnStringNotLikeIfExists', {
      StringNotLikeIfExists: {
        'aws:PrincipalArn': 'arn:aws:iam::111111111111:role/ExampleRole'
      }
    }),
    expected: 'public',
    publicStatements: [{ index: 1, sid: 'PrincipalArnStringNotLikeIfExists' }]
  },
  {
    name: 'PrincipalAccount exact condition is non-public',
    policy: wildcardAllowWithCondition('PrincipalAccountExact', {
      StringEquals: { 'aws:PrincipalAccount': '111111111111' }
    }),
    expected: 'nonPublic'
  },
  {
    name: 'PrincipalAccount wildcard condition is public',
    policy: wildcardAllowWithCondition('PrincipalAccountWildcard', {
      StringLike: { 'aws:PrincipalAccount': '1111*' }
    }),
    expected: 'public',
    publicStatements: [{ index: 1, sid: 'PrincipalAccountWildcard' }]
  },
  {
    name: 'PrincipalOrgID exact condition is non-public',
    policy: wildcardAllowWithCondition('PrincipalOrgExact', {
      StringEquals: { 'aws:PrincipalOrgID': 'o-8jc0e05m21' }
    }),
    expected: 'nonPublic'
  },
  {
    name: 'PrincipalOrgID wildcard condition is public',
    policy: wildcardAllowWithCondition('PrincipalOrgWildcard', {
      StringLike: { 'aws:PrincipalOrgID': 'o-*' }
    }),
    expected: 'public',
    publicStatements: [{ index: 1, sid: 'PrincipalOrgWildcard' }]
  },
  {
    name: 'PrincipalOrgID StringNotEquals condition is public',
    policy: wildcardAllowWithCondition('PrincipalOrgNotEquals', {
      StringNotEquals: { 'aws:PrincipalOrgID': 'o-8jc0e05m21' }
    }),
    expected: 'public',
    publicStatements: [{ index: 1, sid: 'PrincipalOrgNotEquals' }]
  },
  {
    name: 'PrincipalOrgPaths exact condition is non-public',
    policy: wildcardAllowWithCondition('PrincipalOrgPathsExact', {
      StringEquals: { 'aws:PrincipalOrgPaths': 'o-8jc0e05m21/r-root/ou-example/' }
    }),
    expected: 'nonPublic'
  },
  {
    name: 'PrincipalOrgPaths wildcard suffix condition is non-public',
    policy: wildcardAllowWithCondition('PrincipalOrgPathsWildcardSuffix', {
      StringLike: { 'aws:PrincipalOrgPaths': 'o-8jc0e05m21/r-root/ou-example/*' }
    }),
    expected: 'nonPublic'
  },
  {
    name: 'PrincipalTag exact condition is public',
    policy: wildcardAllowWithCondition('PrincipalTagExact', {
      StringEquals: { 'aws:PrincipalTag/Department': 'Engineering' }
    }),
    expected: 'public',
    publicStatements: [{ index: 1, sid: 'PrincipalTagExact' }]
  },
  {
    name: 'PrincipalIsAWSService true condition is non-public',
    policy: wildcardAllowWithCondition('PrincipalIsServiceTrue', {
      Bool: { 'aws:PrincipalIsAWSService': 'true' }
    }),
    expected: 'nonPublic'
  },
  {
    name: 'PrincipalIsAWSService true with StringEquals is non-public',
    policy: wildcardAllowWithCondition('PrincipalIsServiceStringEqualsTrue', {
      StringEquals: { 'aws:PrincipalIsAWSService': 'true' }
    }),
    expected: 'nonPublic'
  },
  {
    name: 'PrincipalIsAWSService true with StringEqualsIgnoreCase is non-public',
    policy: wildcardAllowWithCondition('PrincipalIsServiceIgnoreCaseTrue', {
      StringEqualsIgnoreCase: { 'aws:PrincipalIsAWSService': 'TRUE' }
    }),
    expected: 'nonPublic'
  },
  {
    name: 'PrincipalIsAWSService true with StringLike is non-public',
    policy: wildcardAllowWithCondition('PrincipalIsServiceStringLikeTrue', {
      StringLike: { 'aws:PrincipalIsAWSService': 'true' }
    }),
    expected: 'nonPublic'
  },
  {
    name: 'PrincipalIsAWSService false condition is public',
    policy: wildcardAllowWithCondition('PrincipalIsServiceFalse', {
      Bool: { 'aws:PrincipalIsAWSService': 'false' }
    }),
    expected: 'public',
    publicStatements: [{ index: 1, sid: 'PrincipalIsServiceFalse' }]
  },
  {
    name: 'PrincipalServiceName wildcard service pattern is non-public',
    policy: wildcardAllowWithCondition('PrincipalServiceNameWildcard', {
      StringLike: { 'aws:PrincipalServiceName': '*.amazonaws.com' }
    }),
    expected: 'nonPublic'
  },
  {
    name: 'PrincipalServiceNamesList exact service name is non-public',
    policy: wildcardAllowWithCondition('PrincipalServiceNamesListExact', {
      'ForAnyValue:StringEquals': { 'aws:PrincipalServiceNamesList': 'cloudfront.amazonaws.com' }
    }),
    expected: 'nonPublic'
  },
  {
    name: 'PrincipalType condition is public',
    policy: wildcardAllowWithCondition('PrincipalType', {
      StringEquals: { 'aws:PrincipalType': 'AssumedRole' }
    }),
    expected: 'public',
    publicStatements: [{ index: 1, sid: 'PrincipalType' }]
  },
  {
    name: 'userid fixed prefix wildcard session suffix is non-public',
    policy: wildcardAllowWithCondition('UserIdWildcardSession', {
      StringLike: { 'aws:userid': 'AROAEXAMPLE:*' }
    }),
    expected: 'nonPublic'
  },
  {
    name: 'username exact condition is public',
    policy: wildcardAllowWithCondition('UsernameExact', {
      StringEquals: { 'aws:username': 'alice' }
    }),
    expected: 'public',
    publicStatements: [{ index: 1, sid: 'UsernameExact' }]
  },
  {
    name: 'SourceVpc exact condition is non-public',
    policy: wildcardAllowWithCondition('SourceVpcExact', {
      StringEquals: { 'aws:SourceVpc': 'vpc-0123456789abcdef0' }
    }),
    expected: 'nonPublic'
  },
  {
    name: 'SourceVpc literal StringLike condition is non-public',
    policy: wildcardAllowWithCondition('SourceVpcStringLikeLiteral', {
      StringLike: { 'aws:SourceVpc': 'vpc-0123456789abcdef0' }
    }),
    expected: 'nonPublic'
  },
  {
    name: 'SourceVpc StringEqualsIgnoreCase condition is non-public',
    policy: wildcardAllowWithCondition('SourceVpcIgnoreCase', {
      StringEqualsIgnoreCase: { 'aws:SourceVpc': 'vpc-0123456789abcdef0' }
    }),
    expected: 'nonPublic'
  },
  {
    name: 'SourceVpc wildcard condition is public',
    policy: wildcardAllowWithCondition('SourceVpcWildcard', {
      StringLike: { 'aws:SourceVpc': 'vpc-*' }
    }),
    expected: 'public',
    publicStatements: [{ index: 1, sid: 'SourceVpcWildcard' }]
  },
  {
    name: 'SourceVpcArn exact condition is non-public',
    policy: wildcardAllowWithCondition('SourceVpcArnExact', {
      ArnEquals: {
        'aws:SourceVpcArn': 'arn:aws:ec2:us-east-1:111111111111:vpc/vpc-0123456789abcdef0'
      }
    }),
    expected: 'nonPublic'
  },
  {
    name: 'SourceVpcArn wildcard resource is public in the conservative runtime classifier',
    policy: wildcardAllowWithCondition('SourceVpcArnWildcard', {
      ArnLike: { 'aws:SourceVpcArn': 'arn:aws:ec2:us-east-1:111111111111:vpc/*' }
    }),
    expected: 'public',
    publicStatements: [{ index: 1, sid: 'SourceVpcArnWildcard' }]
  },
  {
    name: 'SourceVpce exact condition is non-public',
    policy: wildcardAllowWithCondition('SourceVpceExact', {
      StringEquals: { 'aws:SourceVpce': 'vpce-0123456789abcdef0' }
    }),
    expected: 'nonPublic'
  },
  {
    name: 'VpceAccount exact condition is non-public',
    policy: wildcardAllowWithCondition('VpceAccountExact', {
      StringEquals: { 'aws:VpceAccount': '111111111111' }
    }),
    expected: 'nonPublic'
  },
  {
    name: 'VpceOrgID exact condition is non-public',
    policy: wildcardAllowWithCondition('VpceOrgExact', {
      StringEquals: { 'aws:VpceOrgID': 'o-8jc0e05m21' }
    }),
    expected: 'nonPublic'
  },
  {
    name: 'VpceOrgPaths wildcard suffix condition is non-public',
    policy: wildcardAllowWithCondition('VpceOrgPathsWildcardSuffix', {
      StringLike: { 'aws:VpceOrgPaths': 'o-8jc0e05m21/r-root/ou-example/*' }
    }),
    expected: 'nonPublic'
  },
  {
    name: 'VpcSourceIp alone is public',
    policy: wildcardAllowWithCondition('VpcSourceIp', {
      IpAddress: { 'aws:VpcSourceIp': '10.0.0.0/8' }
    }),
    expected: 'public',
    publicStatements: [{ index: 1, sid: 'VpcSourceIp' }]
  },
  {
    name: 'SourceIp narrow public IPv4 range is non-public',
    policy: wildcardAllowWithCondition('SourceIpNarrow', {
      IpAddress: { 'aws:SourceIp': '203.0.113.10/32' }
    }),
    expected: 'nonPublic'
  },
  {
    name: 'SourceIp RFC1918 private IPv4 range is non-public',
    policy: wildcardAllowWithCondition('SourceIpPrivate', {
      IpAddress: { 'aws:SourceIp': '10.0.0.0/8' }
    }),
    expected: 'nonPublic'
  },
  {
    name: 'SourceIp broad public IPv4 range is public',
    policy: wildcardAllowWithCondition('SourceIpBroad', {
      IpAddress: { 'aws:SourceIp': '0.0.0.0/1' }
    }),
    expected: 'public',
    publicStatements: [{ index: 1, sid: 'SourceIpBroad' }]
  },
  {
    name: 'SourceIp IPv6 /32 range is non-public',
    policy: wildcardAllowWithCondition('SourceIpIpv6Narrow', {
      IpAddress: { 'aws:SourceIp': '2001:db8::/32' }
    }),
    expected: 'nonPublic'
  },
  {
    name: 'SourceIp IPv6 range broader than /32 is public',
    policy: wildcardAllowWithCondition('SourceIpIpv6Broad', {
      IpAddress: { 'aws:SourceIp': '2001:db8::/31' }
    }),
    expected: 'public',
    publicStatements: [{ index: 1, sid: 'SourceIpIpv6Broad' }]
  },
  {
    name: 'SourceArn exact condition is non-public',
    policy: wildcardAllowWithCondition('SourceArnExact', {
      ArnEquals: {
        'aws:SourceArn': 'arn:aws:cloudfront::111111111111:distribution/EXAMPLE'
      }
    }),
    expected: 'nonPublic'
  },
  {
    name: 'SourceAccount exact condition is non-public',
    policy: wildcardAllowWithCondition('SourceAccountExact', {
      StringEquals: { 'aws:SourceAccount': '111111111111' }
    }),
    expected: 'nonPublic'
  },
  {
    name: 'SecureTransport true condition is public',
    policy: wildcardAllowWithCondition('SecureTransport', {
      Bool: { 'aws:SecureTransport': 'true' }
    }),
    expected: 'public',
    publicStatements: [{ index: 1, sid: 'SecureTransport' }]
  },
  {
    name: 'Deny-only wildcard policy is non-public',
    policy: {
      Version: '2012-10-17',
      Statement: [
        {
          Sid: 'DenyOnly',
          Effect: 'Deny',
          Principal: '*',
          Action: 's3:GetObject',
          Resource: objectArn
        }
      ]
    },
    expected: 'nonPublic'
  },
  {
    name: 'specific allow plus wildcard deny is non-public',
    policy: {
      Version: '2012-10-17',
      Statement: [
        {
          Sid: 'SpecificAllow',
          Effect: 'Allow',
          Principal: { AWS: 'arn:aws:iam::222222222222:role/ExampleRole' },
          Action: 's3:GetObject',
          Resource: objectArn
        },
        {
          Sid: 'WildcardDeny',
          Effect: 'Deny',
          Principal: '*',
          Action: 's3:GetObject',
          Resource: objectArn
        }
      ]
    },
    expected: 'nonPublic'
  },
  {
    name: 'wildcard allow narrowed by deny is runtime-public',
    policy: {
      Version: '2012-10-17',
      Statement: [
        {
          Sid: 'WildcardAllow',
          Effect: 'Allow',
          Principal: '*',
          Action: 's3:GetObject',
          Resource: objectArn
        },
        {
          Sid: 'DenyOutsideOrg',
          Effect: 'Deny',
          Principal: '*',
          Action: 's3:GetObject',
          Resource: objectArn,
          Condition: { StringNotEquals: { 'aws:PrincipalOrgID': 'o-8jc0e05m21' } }
        }
      ]
    },
    expected: 'public',
    publicStatements: [{ index: 1, sid: 'WildcardAllow' }]
  },
  {
    name: 'mixed public statement and specific role statement is public',
    policy: {
      Version: '2012-10-17',
      Statement: [
        {
          Sid: 'SpecificRole',
          Effect: 'Allow',
          Principal: { AWS: 'arn:aws:iam::222222222222:role/ExampleRole' },
          Action: 's3:GetObject',
          Resource: objectArn
        },
        {
          Sid: 'PublicStatement',
          Effect: 'Allow',
          Principal: '*',
          Action: 's3:GetBucketLocation',
          Resource: bucketArn
        }
      ]
    },
    expected: 'public',
    publicStatements: [{ index: 2, sid: 'PublicStatement' }]
  },
  {
    name: 'mixed org-constrained wildcard and specific role is non-public',
    policy: {
      Version: '2012-10-17',
      Statement: [
        wildcardAllowStatement('OrgConstrained', {
          StringEquals: { 'aws:PrincipalOrgID': 'o-8jc0e05m21' }
        }),
        {
          Sid: 'SpecificRole',
          Effect: 'Allow',
          Principal: { AWS: 'arn:aws:iam::222222222222:role/ExampleRole' },
          Action: 's3:GetObject',
          Resource: objectArn
        }
      ]
    },
    expected: 'nonPublic'
  }
]

describe('classifyS3RuntimePublicBucketPolicy', () => {
  it.each(classifierCases)('$name', (testCase) => {
    //Given a loaded S3 bucket policy
    const policy = loadPolicy(testCase.policy, { name: 'ResourcePolicy' })

    //When the policy is classified for runtime RestrictPublicBuckets behavior
    const result = classifyS3RuntimePublicBucketPolicy(policy)

    //Then the classification should match the expected result
    expect(result.result).toBe(testCase.expected)
    if (testCase.expected === 'public') {
      expect(result).toEqual({
        result: 'public',
        publicStatements: testCase.publicStatements
      })
    }
  })
})

function allowPolicy(options: { Sid: string; Principal: unknown }): object {
  return {
    Version: '2012-10-17',
    Statement: [
      {
        Sid: options.Sid,
        Effect: 'Allow',
        Principal: options.Principal,
        Action: 's3:GetObject',
        Resource: objectArn
      }
    ]
  }
}

function wildcardAllowWithCondition(sid: string, condition: object): object {
  return {
    Version: '2012-10-17',
    Statement: [wildcardAllowStatement(sid, condition)]
  }
}

function wildcardAllowStatement(sid: string, condition: object): object {
  return {
    Sid: sid,
    Effect: 'Allow',
    Principal: '*',
    Action: 's3:GetObject',
    Resource: objectArn,
    Condition: condition
  }
}
