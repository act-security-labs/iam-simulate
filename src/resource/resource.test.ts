import {
  loadPolicy,
  type NotResourceStatement,
  type ResourceStatement
} from '@actsecurity/iam-policy'
import { describe, expect, it } from 'vitest'
import type { ResourceExplain } from '../explain/statementExplain.js'
import type { PolicyType } from '../policyType.js'
import { AwsRequestImpl } from '../request/request.js'
import { RequestContextImpl } from '../requestContext.js'
import {
  requestMatchesNotResources,
  requestMatchesResources,
  resourcePatternOverlap
} from './resource.js'

type ResourceStatements =
  | {
      resourceStatements: string[]
      notResourceStatements?: never
    }
  | {
      resourceStatements?: never
      notResourceStatements: string[]
    }

type ResourceTest = {
  name?: string
  only?: true
  effect?: 'Allow' | 'Deny'
  policyType?: PolicyType
  resource: {
    resource: string
    accountId: string
  }
  wildcardOnlyAction?: boolean
  expectMatch: boolean
  context?: Record<string, string | string[]>
  explains: ResourceExplain[]
} & ResourceStatements

const resourceTests: ResourceTest[] = [
  {
    name: 'should match wildcard',
    resourceStatements: ['*'],
    resource: {
      resource: 'arn:aws:s3:::my_corporate_bucket',
      accountId: '123456789012'
    },
    expectMatch: true,
    explains: [
      {
        resource: '*',
        matches: true
      }
    ]
  },
  {
    name: 'should fail if different partition',
    resourceStatements: ['arn:aws:s3:::my_corporate_bucket'],
    resource: {
      resource: 'arn:aws-gov:s3:::my_corporate_bucket',
      accountId: '123456789012'
    },
    expectMatch: false,
    explains: [
      {
        resource: 'arn:aws:s3:::my_corporate_bucket',
        matches: false,
        errors: ['Partition does not match']
      }
    ]
  },
  {
    name: 'should match a wildcard partition',
    resourceStatements: ['arn:*:s3:::my_corporate_bucket'],
    resource: {
      resource: 'arn:aws:s3:::my_corporate_bucket',
      accountId: '123456789012'
    },
    expectMatch: true,
    explains: [
      {
        resource: 'arn:*:s3:::my_corporate_bucket',
        matches: true
      }
    ]
  },
  {
    name: 'should match a question mark partition',
    resourceStatements: ['arn:???:s3:::my_corporate_bucket'],
    resource: {
      resource: 'arn:aws:s3:::my_corporate_bucket',
      accountId: '123456789012'
    },
    expectMatch: true,
    explains: [
      {
        resource: 'arn:???:s3:::my_corporate_bucket',
        matches: true
      }
    ]
  },
  {
    name: 'should match a policy resource with leading question mark wildcards against a wildcard request resource',
    resourceStatements: ['arn:aws:s3:::??-example-bucket/data/*/_logs/*'],
    resource: {
      resource: 'arn:aws:s3:::ab-example-bucket/data/v1/table/_logs/*',
      accountId: '123456789012'
    },
    expectMatch: true,
    explains: [
      {
        resource: 'arn:aws:s3:::??-example-bucket/data/*/_logs/*',
        matches: true
      }
    ]
  },
  {
    name: 'Should fail if different service',
    resourceStatements: ['arn:aws:s3:::my_corporate_bucket'],
    resource: {
      resource: 'arn:aws:sqs:::my_corporate_bucket',
      accountId: '123456789012'
    },
    expectMatch: false,
    explains: [
      {
        resource: 'arn:aws:s3:::my_corporate_bucket',
        matches: false,
        errors: ['Service does not match'],
        mismatchReason: 'serviceMismatch'
      }
    ]
  },
  {
    name: 'should match a wildcard service',
    resourceStatements: ['arn:aws:*:::my_corporate_bucket'],
    resource: {
      resource: 'arn:aws:s3:::my_corporate_bucket',
      accountId: '123456789012'
    },
    expectMatch: true,
    explains: [
      {
        resource: 'arn:aws:*:::my_corporate_bucket',
        matches: true
      }
    ]
  },
  {
    name: 'should not match if different region',
    resourceStatements: ['arn:aws:ec2:us-east-1:123456789012:instance/12345'],
    resource: {
      resource: 'arn:aws:ec2:us-west-1:123456789012:instance/12345',
      accountId: '123456789012'
    },
    expectMatch: false,
    explains: [
      {
        resource: 'arn:aws:ec2:us-east-1:123456789012:instance/12345',
        matches: false,
        errors: ['Region does not match']
      }
    ]
  },
  {
    name: 'should match a wildcard region',
    resourceStatements: ['arn:aws:ec2:*:123456789012:instance/12345'],
    resource: {
      resource: 'arn:aws:ec2:us-east-1:123456789012:instance/12345',
      accountId: '123456789012'
    },
    expectMatch: true,
    explains: [
      {
        resource: 'arn:aws:ec2:*:123456789012:instance/12345',
        matches: true
      }
    ]
  },
  {
    name: 'should not match if a different account',
    resourceStatements: ['arn:aws:ec2:us-east-1:123456789012:instance/12345'],
    resource: {
      resource: 'arn:aws:ec2:us-east-1:987654321012:instance/12345',
      accountId: '123456789012'
    },
    expectMatch: false,
    explains: [
      {
        resource: 'arn:aws:ec2:us-east-1:123456789012:instance/12345',
        matches: false,
        errors: ['Account does not match']
      }
    ]
  },
  {
    name: 'should match a wildcard account',
    resourceStatements: ['arn:aws:ec2:us-east-1:*:instance/12345'],
    resource: {
      resource: 'arn:aws:ec2:us-east-1:123456789012:instance/12345',
      accountId: '123456789012'
    },
    expectMatch: true,
    explains: [
      {
        resource: 'arn:aws:ec2:us-east-1:*:instance/12345',
        matches: true
      }
    ]
  },
  {
    name: 'should match a wildcard resource',
    resourceStatements: ['arn:aws:ec2:us-east-1:123456789012:instance/*'],
    resource: {
      resource: 'arn:aws:ec2:us-east-1:123456789012:instance/12345',
      accountId: '123456789012'
    },
    expectMatch: true,
    explains: [
      {
        resource: 'arn:aws:ec2:us-east-1:123456789012:instance/*',
        matches: true
      }
    ]
  },
  {
    name: 'should not match a wildcard product',
    resourceStatements: ['arn:aws:ec2:us-east-1:123456789012:*/12345'],
    resource: {
      resource: 'arn:aws:ec2:us-east-1:123456789012:instance/12345',
      accountId: '123456789012'
    },
    expectMatch: false,
    explains: [
      {
        resource: 'arn:aws:ec2:us-east-1:123456789012:*/12345',
        matches: false,
        errors: ['Product does not match']
      }
    ]
  },
  {
    name: 'should match a wildcard resource with a colon separator',
    resourceStatements: ['arn:aws:ec2:us-east-1:123456789012:instance:*'],
    resource: {
      resource: 'arn:aws:ec2:us-east-1:123456789012:instance:12345',
      accountId: '123456789012'
    },
    expectMatch: true,
    explains: [
      {
        resource: 'arn:aws:ec2:us-east-1:123456789012:instance:*',
        matches: true
      }
    ]
  },
  {
    name: 'should not match a wildcard product with a colon separator',
    resourceStatements: ['arn:aws:ec2:us-east-1:123456789012:*:12345'],
    resource: {
      resource: 'arn:aws:ec2:us-east-1:123456789012:instance:12345',
      accountId: '123456789012'
    },
    expectMatch: false,
    explains: [
      {
        resource: 'arn:aws:ec2:us-east-1:123456789012:*:12345',
        matches: false,
        errors: ['Product does not match']
      }
    ]
  },
  {
    name: 'should return no match if the s3 bucket name is different',
    resourceStatements: ['arn:aws:s3:::my_corporate_bucket'],
    resource: {
      resource: 'arn:aws:s3:::wildly_different_bucket',
      accountId: '123456789012'
    },
    expectMatch: false,
    explains: [
      {
        resource: 'arn:aws:s3:::my_corporate_bucket',
        matches: false
      }
    ]
  },
  {
    name: 'should return no match on an s3 object if the bucket is different',
    resourceStatements: ['arn:aws:s3:::my_corporate_bucket/*'],
    resource: {
      resource: 'arn:aws:s3:::other_bucket/secret.txt',
      accountId: '123456789012'
    },
    expectMatch: false,
    explains: [
      {
        resource: 'arn:aws:s3:::my_corporate_bucket/*',
        matches: false
      }
    ]
  },
  {
    name: 'should return no match on an s3 object if the bucket is the same but the object is different',
    resourceStatements: ['arn:aws:s3:::my_corporate_bucket/foo/*'],
    resource: {
      resource: 'arn:aws:s3:::my_corporate_bucket/bar/secret.txt',
      accountId: '123456789012'
    },
    expectMatch: false,
    explains: [
      {
        resource: 'arn:aws:s3:::my_corporate_bucket/foo/*',
        matches: false
      }
    ]
  },
  {
    name: 'should replace a context variable in the resource',
    resourceStatements: ['arn:aws:ec2:us-east-1:123456789012:instance/${aws:PrincipalTag/Foo}'],
    resource: {
      resource: 'arn:aws:ec2:us-east-1:123456789012:instance/bar',
      accountId: '123456789012'
    },
    expectMatch: true,
    context: {
      'aws:PrincipalTag/Foo': 'bar'
    },
    explains: [
      {
        resource: 'arn:aws:ec2:us-east-1:123456789012:instance/${aws:PrincipalTag/Foo}',
        resolvedValue: 'arn:aws:ec2:us-east-1:123456789012:instance/bar',
        matches: true
      }
    ]
  },
  {
    name: 'should not replace a context variable if a string array',
    resourceStatements: ['arn:aws:ec2:us-east-1:123456789012:instance/${aws:PrincipalTag/Foo}'],
    resource: {
      resource: 'arn:aws:ec2:us-east-1:123456789012:instance/bar',
      accountId: '123456789012'
    },
    expectMatch: false,
    context: {
      'aws:PrincipalTag/Foo': ['bar', 'baz']
    },
    explains: [
      {
        resource: 'arn:aws:ec2:us-east-1:123456789012:instance/${aws:PrincipalTag/Foo}',
        matches: false,
        errors: [
          '{aws:PrincipalTag/Foo} is a multi value context key, and cannot be used for replacement. This will never match'
        ]
      }
    ]
  },
  {
    name: 'should replace a context variable with a default value',
    resourceStatements: [
      "arn:aws:ec2:us-east-1:123456789012:instance/${aws:PrincipalTag/Foo, 'defaultfoo'}"
    ],
    resource: {
      resource: 'arn:aws:ec2:us-east-1:123456789012:instance/bar',
      accountId: '123456789012'
    },
    expectMatch: true,
    context: {
      'aws:PrincipalTag/Foo': 'bar'
    },
    explains: [
      {
        resource:
          "arn:aws:ec2:us-east-1:123456789012:instance/${aws:PrincipalTag/Foo, 'defaultfoo'}",
        resolvedValue: 'arn:aws:ec2:us-east-1:123456789012:instance/bar',
        matches: true
      }
    ]
  },
  {
    name: 'should use a default value if a context variable does not exist',
    resourceStatements: [
      "arn:aws:ec2:us-east-1:123456789012:instance/${aws:PrincipalTag/Foo, 'defaultfoo'}"
    ],
    resource: {
      resource: 'arn:aws:ec2:us-east-1:123456789012:instance/defaultfoo',
      accountId: '123456789012'
    },
    expectMatch: true,
    explains: [
      {
        resource:
          "arn:aws:ec2:us-east-1:123456789012:instance/${aws:PrincipalTag/Foo, 'defaultfoo'}",
        resolvedValue: 'arn:aws:ec2:us-east-1:123456789012:instance/defaultfoo',
        matches: true
      }
    ]
  },
  {
    name: 'should match if only one value matches',
    resourceStatements: [
      'arn:aws:s3:::government_secrets',
      'arn:aws:ec2:us-east-1:123456789012:instance/${aws:PrincipalTag/Foo}'
    ],
    resource: {
      resource: 'arn:aws:ec2:us-east-1:123456789012:instance/bar',
      accountId: '123456789012'
    },
    expectMatch: true,
    context: {
      'aws:PrincipalTag/Foo': 'bar'
    },
    explains: [
      {
        resource: 'arn:aws:s3:::government_secrets',
        matches: false,
        errors: ['Service does not match']
      },
      {
        resource: 'arn:aws:ec2:us-east-1:123456789012:instance/${aws:PrincipalTag/Foo}',
        resolvedValue: 'arn:aws:ec2:us-east-1:123456789012:instance/bar',
        matches: true
      }
    ]
  },
  {
    name: 'should match when policy is a superset of a request wildcard',
    resourceStatements: ['arn:aws:s3:::my_corporate_bucket/*'],
    effect: 'Allow',
    resource: {
      resource: 'arn:aws:s3:::my_corporate_bucket/foo*',
      accountId: '123456789012'
    },
    expectMatch: true,
    explains: [
      {
        resource: 'arn:aws:s3:::my_corporate_bucket/*',
        matches: true
      }
    ]
  },
  {
    name: 'Resource & Allow when policy is a subset of a request wildcard',
    resourceStatements: ['arn:aws:s3:::my_corporate_bucket/foo*'],
    effect: 'Allow',
    resource: {
      resource: 'arn:aws:s3:::my_corporate_bucket/*',
      accountId: '123456789012'
    },
    expectMatch: true,
    explains: [
      {
        resource: 'arn:aws:s3:::my_corporate_bucket/foo*',
        matches: true
      }
    ]
  },
  {
    name: 'should not match when policy and request wildcards do not overlap',
    resourceStatements: ['arn:aws:s3:::my_corporate_bucket/bar*'],
    effect: 'Allow',
    resource: {
      resource: 'arn:aws:s3:::my_corporate_bucket/foo*',
      accountId: '123456789012'
    },
    expectMatch: false,
    explains: [
      {
        resource: 'arn:aws:s3:::my_corporate_bucket/bar*',
        matches: false
      }
    ]
  },
  {
    name: 'Resource & Allow falls through wildcard overlap check and returns detailed mismatch',
    resourceStatements: ['arn:aws:ec2:us-east-1:123456789012:instance/i-12345'],
    effect: 'Allow',
    resource: {
      resource: 'arn:aws:ec2:us-west-*:123456789012:instance/i-*',
      accountId: '123456789012'
    },
    expectMatch: false,
    explains: [
      {
        resource: 'arn:aws:ec2:us-east-1:123456789012:instance/i-12345',
        matches: false,
        errors: ['Region does not match']
      }
    ]
  },
  {
    name: 'should match when request wildcard is in a non-resource segment',
    resourceStatements: ['arn:aws:ec2:us-east-1:123456789012:instance/i-123'],
    effect: 'Allow',
    resource: {
      resource: 'arn:aws:ec2:*:123456789012:instance/i-123',
      accountId: '123456789012'
    },
    expectMatch: true,
    explains: [
      {
        resource: 'arn:aws:ec2:us-east-1:123456789012:instance/i-123',
        matches: true
      }
    ]
  },
  {
    name: 'should match when request is a single wildcard',
    resourceStatements: ['arn:aws:s3:::my_corporate_bucket'],
    effect: 'Allow',
    resource: {
      resource: '*',
      accountId: '123456789012'
    },
    expectMatch: true,
    explains: [
      {
        resource: 'arn:aws:s3:::my_corporate_bucket',
        matches: true
      }
    ]
  },
  {
    name: 'should match when policy and request wildcards are identical',
    resourceStatements: ['arn:aws:s3:::my_corporate_bucket/*'],
    effect: 'Allow',
    resource: {
      resource: 'arn:aws:s3:::my_corporate_bucket/*',
      accountId: '123456789012'
    },
    expectMatch: true,
    explains: [
      {
        resource: 'arn:aws:s3:::my_corporate_bucket/*',
        matches: true
      }
    ]
  },
  {
    name: 'should match when policy and request wildcards are identical in a non-resource segment',
    resourceStatements: ['arn:aws:ec2:*:123456789012:instance/*'],
    effect: 'Allow',
    resource: {
      resource: 'arn:aws:ec2:*:123456789012:instance/*',
      accountId: '123456789012'
    },
    expectMatch: true,
    explains: [
      {
        resource: 'arn:aws:ec2:*:123456789012:instance/*',
        matches: true
      }
    ]
  },
  {
    name: 'Allow Resource Statement Does NotMatch Wildcard',
    resourceStatements: ['arn:aws:s3:::my_corporate_bucket/file.txt'],
    effect: 'Allow',
    resource: {
      resource: 'arn:aws:s3:::my_corporate_bucket/private/*',
      accountId: '123456789012'
    },
    expectMatch: false,
    explains: [
      {
        resource: 'arn:aws:s3:::my_corporate_bucket/file.txt',
        matches: false
      }
    ]
  },

  {
    name: 'should match when policy and request wildcards are identical for deny',
    resourceStatements: ['arn:aws:s3:::my_corporate_bucket/*'],
    effect: 'Deny',
    resource: {
      resource: 'arn:aws:s3:::my_corporate_bucket/*',
      accountId: '123456789012'
    },
    expectMatch: true,
    explains: [
      {
        resource: 'arn:aws:s3:::my_corporate_bucket/*',
        matches: true
      }
    ]
  },
  {
    name: 'should match when policy and request wildcards are identical in a non-resource segment for deny',
    resourceStatements: ['arn:aws:ec2:*:123456789012:instance/*'],
    effect: 'Deny',
    resource: {
      resource: 'arn:aws:ec2:*:123456789012:instance/*',
      accountId: '123456789012'
    },
    expectMatch: true,
    explains: [
      {
        resource: 'arn:aws:ec2:*:123456789012:instance/*',
        matches: true
      }
    ]
  },
  {
    name: 'should not match when policy is a subset of a request wildcard for deny',
    resourceStatements: ['arn:aws:s3:::my_corporate_bucket/foo*'],
    effect: 'Deny',
    resource: {
      resource: 'arn:aws:s3:::my_corporate_bucket/*',
      accountId: '123456789012'
    },
    expectMatch: false,
    explains: [
      {
        resource: 'arn:aws:s3:::my_corporate_bucket/foo*',
        matches: false
      }
    ]
  },
  {
    name: 'Resource & Deny when request wildcard is in a non-resource segment for deny',
    resourceStatements: ['arn:aws:ec2:us-east-1:123456789012:instance/i-123'],
    effect: 'Deny',
    resource: {
      resource: 'arn:aws:ec2:*:123456789012:instance/i-123',
      accountId: '123456789012'
    },
    expectMatch: false,
    explains: [
      {
        resource: 'arn:aws:ec2:us-east-1:123456789012:instance/i-123',
        matches: false
      }
    ]
  },
  {
    name: 'should not match when request is a single wildcard for deny',
    resourceStatements: ['arn:aws:s3:::my_corporate_bucket'],
    effect: 'Deny',
    resource: {
      resource: '*',
      accountId: '123456789012'
    },
    expectMatch: false,
    explains: [
      {
        resource: 'arn:aws:s3:::my_corporate_bucket',
        matches: false
      }
    ]
  },
  {
    name: 'should match when policy is a superset of a request wildcard for deny',
    resourceStatements: ['arn:aws:s3:::my_corporate_bucket/*'],
    effect: 'Deny',
    resource: {
      resource: 'arn:aws:s3:::my_corporate_bucket/foo*',
      accountId: '123456789012'
    },
    expectMatch: true,
    explains: [
      {
        resource: 'arn:aws:s3:::my_corporate_bucket/*',
        matches: true
      }
    ]
  },
  {
    name: 'Resource & Deny falls through wildcard overlap check and still matches for policy supersets',
    resourceStatements: ['arn:aws:ec2:us-*:123456789012:instance/i-*'],
    effect: 'Deny',
    resource: {
      resource: 'arn:aws:ec2:us-east-*:123456789012:instance/i-123*',
      accountId: '123456789012'
    },
    expectMatch: true,
    explains: [
      {
        resource: 'arn:aws:ec2:us-*:123456789012:instance/i-*',
        matches: true
      }
    ]
  },
  {
    name: 'should not match when policy and request wildcards do not overlap for deny',
    resourceStatements: ['arn:aws:s3:::my_corporate_bucket/bar*'],
    effect: 'Deny',
    resource: {
      resource: 'arn:aws:s3:::my_corporate_bucket/foo*',
      accountId: '123456789012'
    },
    expectMatch: false,
    explains: [
      {
        resource: 'arn:aws:s3:::my_corporate_bucket/bar*',
        matches: false
      }
    ]
  },
  {
    name: 'wildcard-only action: should match when policy resource is *',
    resourceStatements: ['*'],
    wildcardOnlyAction: true,
    resource: {
      resource: '*',
      accountId: '123456789012'
    },
    expectMatch: true,
    explains: [
      {
        resource: '*',
        matches: true
      }
    ]
  },
  {
    name: 'wildcard-only action: should not match Allow/Resource with specific ARN',
    resourceStatements: ['arn:aws:s3:::my-bucket'],
    wildcardOnlyAction: true,
    resource: {
      resource: '*',
      accountId: '123456789012'
    },
    expectMatch: false,
    explains: [
      {
        resource: 'arn:aws:s3:::my-bucket',
        matches: false
      }
    ]
  },
  {
    name: 'wildcard-only action: should not match Allow/Resource with wildcard ARN',
    resourceStatements: ['arn:aws:s3:::my-bucket/*'],
    wildcardOnlyAction: true,
    resource: {
      resource: '*',
      accountId: '123456789012'
    },
    expectMatch: false,
    explains: [
      {
        resource: 'arn:aws:s3:::my-bucket/*',
        matches: false
      }
    ]
  },
  {
    name: 'wildcard-only action: should match Allow/Resource when one resource is *',
    resourceStatements: ['arn:aws:s3:::my-bucket', '*'],
    wildcardOnlyAction: true,
    resource: {
      resource: '*',
      accountId: '123456789012'
    },
    expectMatch: true,
    explains: [
      {
        resource: 'arn:aws:s3:::my-bucket',
        matches: false
      },
      {
        resource: '*',
        matches: true
      }
    ]
  },
  {
    name: 'wildcard-only action: should not match Deny/Resource with specific ARN',
    resourceStatements: ['arn:aws:s3:::my-bucket'],
    effect: 'Deny',
    wildcardOnlyAction: true,
    resource: {
      resource: '*',
      accountId: '123456789012'
    },
    expectMatch: false,
    explains: [
      {
        resource: 'arn:aws:s3:::my-bucket',
        matches: false
      }
    ]
  },
  {
    name: 'wildcard-only action: should match Deny/Resource when policy resource is *',
    resourceStatements: ['*'],
    effect: 'Deny',
    wildcardOnlyAction: true,
    resource: {
      resource: '*',
      accountId: '123456789012'
    },
    expectMatch: true,
    explains: [
      {
        resource: '*',
        matches: true
      }
    ]
  },

  // ── Short ARN tests: Identity Policy (Allow) ──────────────────────────
  {
    name: 'identity: P1 arn:aws:sqs matches Q',
    policyType: 'identity',
    resourceStatements: ['arn:aws:sqs'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: true,
    explains: [{ resource: 'arn:aws:sqs', matches: true }]
  },
  {
    name: 'identity: P2 arn:aws:sqs:us-east-1 matches Q',
    policyType: 'identity',
    resourceStatements: ['arn:aws:sqs:us-east-1'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: true,
    explains: [{ resource: 'arn:aws:sqs:us-east-1', matches: true }]
  },
  {
    name: 'identity: P3 arn:aws:sqs:us-east-1:111111111111 matches Q',
    policyType: 'identity',
    resourceStatements: ['arn:aws:sqs:us-east-1:111111111111'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: true,
    explains: [{ resource: 'arn:aws:sqs:us-east-1:111111111111', matches: true }]
  },
  {
    name: 'identity: P4 arn:aws:sqs:* matches Q',
    policyType: 'identity',
    resourceStatements: ['arn:aws:sqs:*'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: true,
    explains: [{ resource: 'arn:aws:sqs:*', matches: true }]
  },
  {
    name: 'identity: P5 arn:aws:sqs:us-east-1:* matches Q',
    policyType: 'identity',
    resourceStatements: ['arn:aws:sqs:us-east-1:*'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: true,
    explains: [{ resource: 'arn:aws:sqs:us-east-1:*', matches: true }]
  },
  {
    name: 'identity: P6 arn:aws:sqs:us-east-1:111111111111:* matches Q',
    policyType: 'identity',
    resourceStatements: ['arn:aws:sqs:us-east-1:111111111111:*'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: true,
    explains: [{ resource: 'arn:aws:sqs:us-east-1:111111111111:*', matches: true }]
  },
  {
    name: 'identity: P7 arn:aws:sqs:us-west-2 does not match Q',
    policyType: 'identity',
    resourceStatements: ['arn:aws:sqs:us-west-2'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [
      { resource: 'arn:aws:sqs:us-west-2', matches: false, errors: ['Region does not match'] }
    ]
  },
  {
    name: 'identity: P8 arn:aws:sqs:us-east-1:222222222222 does not match Q',
    policyType: 'identity',
    resourceStatements: ['arn:aws:sqs:us-east-1:222222222222'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [
      {
        resource: 'arn:aws:sqs:us-east-1:222222222222',
        matches: false,
        errors: ['Account does not match']
      }
    ]
  },
  {
    name: 'identity: P9 arn:aws:sqs:us-east-1:111111111111:other-queue does not match Q',
    policyType: 'identity',
    resourceStatements: ['arn:aws:sqs:us-east-1:111111111111:other-queue'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [{ resource: 'arn:aws:sqs:us-east-1:111111111111:other-queue', matches: false }]
  },
  {
    name: 'identity: P10 exact match Q',
    policyType: 'identity',
    resourceStatements: ['arn:aws:sqs:us-east-1:111111111111:test-queue'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: true,
    explains: [{ resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue', matches: true }]
  },

  // ── Short ARN tests: Session Policy (Allow) ───────────────────────────
  {
    name: 'session: P1 arn:aws:sqs matches Q',
    policyType: 'session',
    resourceStatements: ['arn:aws:sqs'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: true,
    explains: [{ resource: 'arn:aws:sqs', matches: true }]
  },
  {
    name: 'session: P2 arn:aws:sqs:us-east-1 matches Q',
    policyType: 'session',
    resourceStatements: ['arn:aws:sqs:us-east-1'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: true,
    explains: [{ resource: 'arn:aws:sqs:us-east-1', matches: true }]
  },
  {
    name: 'session: P3 arn:aws:sqs:us-east-1:111111111111 matches Q',
    policyType: 'session',
    resourceStatements: ['arn:aws:sqs:us-east-1:111111111111'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: true,
    explains: [{ resource: 'arn:aws:sqs:us-east-1:111111111111', matches: true }]
  },
  {
    name: 'session: P4 arn:aws:sqs:* matches Q',
    policyType: 'session',
    resourceStatements: ['arn:aws:sqs:*'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: true,
    explains: [{ resource: 'arn:aws:sqs:*', matches: true }]
  },
  {
    name: 'session: P5 arn:aws:sqs:us-east-1:* matches Q',
    policyType: 'session',
    resourceStatements: ['arn:aws:sqs:us-east-1:*'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: true,
    explains: [{ resource: 'arn:aws:sqs:us-east-1:*', matches: true }]
  },
  {
    name: 'session: P6 arn:aws:sqs:us-east-1:111111111111:* matches Q',
    policyType: 'session',
    resourceStatements: ['arn:aws:sqs:us-east-1:111111111111:*'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: true,
    explains: [{ resource: 'arn:aws:sqs:us-east-1:111111111111:*', matches: true }]
  },
  {
    name: 'session: P7 arn:aws:sqs:us-west-2 does not match Q',
    policyType: 'session',
    resourceStatements: ['arn:aws:sqs:us-west-2'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [
      { resource: 'arn:aws:sqs:us-west-2', matches: false, errors: ['Region does not match'] }
    ]
  },
  {
    name: 'session: P8 arn:aws:sqs:us-east-1:222222222222 does not match Q',
    policyType: 'session',
    resourceStatements: ['arn:aws:sqs:us-east-1:222222222222'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [
      {
        resource: 'arn:aws:sqs:us-east-1:222222222222',
        matches: false,
        errors: ['Account does not match']
      }
    ]
  },
  {
    name: 'session: P9 arn:aws:sqs:us-east-1:111111111111:other-queue does not match Q',
    policyType: 'session',
    resourceStatements: ['arn:aws:sqs:us-east-1:111111111111:other-queue'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [{ resource: 'arn:aws:sqs:us-east-1:111111111111:other-queue', matches: false }]
  },
  {
    name: 'session: P10 exact match Q',
    policyType: 'session',
    resourceStatements: ['arn:aws:sqs:us-east-1:111111111111:test-queue'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: true,
    explains: [{ resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue', matches: true }]
  },

  // ── Short ARN tests: Permission Boundary (Allow) ──────────────────────
  {
    name: 'pb: P1 arn:aws:sqs matches Q',
    policyType: 'pb',
    resourceStatements: ['arn:aws:sqs'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: true,
    explains: [{ resource: 'arn:aws:sqs', matches: true }]
  },
  {
    name: 'pb: P2 arn:aws:sqs:us-east-1 matches Q',
    policyType: 'pb',
    resourceStatements: ['arn:aws:sqs:us-east-1'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: true,
    explains: [{ resource: 'arn:aws:sqs:us-east-1', matches: true }]
  },
  {
    name: 'pb: P3 arn:aws:sqs:us-east-1:111111111111 matches Q',
    policyType: 'pb',
    resourceStatements: ['arn:aws:sqs:us-east-1:111111111111'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: true,
    explains: [{ resource: 'arn:aws:sqs:us-east-1:111111111111', matches: true }]
  },
  {
    name: 'pb: P4 arn:aws:sqs:* matches Q',
    policyType: 'pb',
    resourceStatements: ['arn:aws:sqs:*'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: true,
    explains: [{ resource: 'arn:aws:sqs:*', matches: true }]
  },
  {
    name: 'pb: P5 arn:aws:sqs:us-east-1:* matches Q',
    policyType: 'pb',
    resourceStatements: ['arn:aws:sqs:us-east-1:*'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: true,
    explains: [{ resource: 'arn:aws:sqs:us-east-1:*', matches: true }]
  },
  {
    name: 'pb: P6 arn:aws:sqs:us-east-1:111111111111:* matches Q',
    policyType: 'pb',
    resourceStatements: ['arn:aws:sqs:us-east-1:111111111111:*'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: true,
    explains: [{ resource: 'arn:aws:sqs:us-east-1:111111111111:*', matches: true }]
  },
  {
    name: 'pb: P7 arn:aws:sqs:us-west-2 does not match Q',
    policyType: 'pb',
    resourceStatements: ['arn:aws:sqs:us-west-2'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [
      { resource: 'arn:aws:sqs:us-west-2', matches: false, errors: ['Region does not match'] }
    ]
  },
  {
    name: 'pb: P8 arn:aws:sqs:us-east-1:222222222222 does not match Q',
    policyType: 'pb',
    resourceStatements: ['arn:aws:sqs:us-east-1:222222222222'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [
      {
        resource: 'arn:aws:sqs:us-east-1:222222222222',
        matches: false,
        errors: ['Account does not match']
      }
    ]
  },
  {
    name: 'pb: P9 arn:aws:sqs:us-east-1:111111111111:other-queue does not match Q',
    policyType: 'pb',
    resourceStatements: ['arn:aws:sqs:us-east-1:111111111111:other-queue'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [{ resource: 'arn:aws:sqs:us-east-1:111111111111:other-queue', matches: false }]
  },
  {
    name: 'pb: P10 exact match Q',
    policyType: 'pb',
    resourceStatements: ['arn:aws:sqs:us-east-1:111111111111:test-queue'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: true,
    explains: [{ resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue', matches: true }]
  },

  // ── Short ARN tests: Resource Policy (Allow) ──────────────────────────
  {
    name: 'resource: P1 arn:aws:sqs does not match Q',
    policyType: 'resource',
    resourceStatements: ['arn:aws:sqs'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [{ resource: 'arn:aws:sqs', matches: false }]
  },
  {
    name: 'resource: P2 arn:aws:sqs:us-east-1 does not match Q',
    policyType: 'resource',
    resourceStatements: ['arn:aws:sqs:us-east-1'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [{ resource: 'arn:aws:sqs:us-east-1', matches: false }]
  },
  {
    name: 'resource: P3 arn:aws:sqs:us-east-1:111111111111 does not match Q',
    policyType: 'resource',
    resourceStatements: ['arn:aws:sqs:us-east-1:111111111111'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [{ resource: 'arn:aws:sqs:us-east-1:111111111111', matches: false }]
  },
  {
    name: 'resource: P4 arn:aws:sqs:* matches Q',
    policyType: 'resource',
    resourceStatements: ['arn:aws:sqs:*'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: true,
    explains: [{ resource: 'arn:aws:sqs:*', matches: true }]
  },
  {
    name: 'resource: P5 arn:aws:sqs:us-east-1:* matches Q',
    policyType: 'resource',
    resourceStatements: ['arn:aws:sqs:us-east-1:*'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: true,
    explains: [{ resource: 'arn:aws:sqs:us-east-1:*', matches: true }]
  },
  {
    name: 'resource: P6 arn:aws:sqs:us-east-1:111111111111:* matches Q',
    policyType: 'resource',
    resourceStatements: ['arn:aws:sqs:us-east-1:111111111111:*'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: true,
    explains: [{ resource: 'arn:aws:sqs:us-east-1:111111111111:*', matches: true }]
  },
  {
    name: 'resource: P7 arn:aws:sqs:us-west-2 does not match Q',
    policyType: 'resource',
    resourceStatements: ['arn:aws:sqs:us-west-2'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [{ resource: 'arn:aws:sqs:us-west-2', matches: false }]
  },
  {
    name: 'resource: P8 arn:aws:sqs:us-east-1:222222222222 does not match Q',
    policyType: 'resource',
    resourceStatements: ['arn:aws:sqs:us-east-1:222222222222'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [{ resource: 'arn:aws:sqs:us-east-1:222222222222', matches: false }]
  },
  {
    name: 'resource: P9 arn:aws:sqs:us-east-1:111111111111:other-queue does not match Q',
    policyType: 'resource',
    resourceStatements: ['arn:aws:sqs:us-east-1:111111111111:other-queue'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [{ resource: 'arn:aws:sqs:us-east-1:111111111111:other-queue', matches: false }]
  },
  {
    name: 'resource: P10 exact match Q',
    policyType: 'resource',
    resourceStatements: ['arn:aws:sqs:us-east-1:111111111111:test-queue'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: true,
    explains: [{ resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue', matches: true }]
  },

  // ── Short ARN tests: SCP (Deny) ───────────────────────────────────────
  {
    name: 'scp: P1 arn:aws:sqs rejected',
    policyType: 'scp',
    effect: 'Deny',
    resourceStatements: ['arn:aws:sqs'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [
      {
        resource: 'arn:aws:sqs',
        matches: false,
        errors: ['Policy resource ARN is not valid for this policy type']
      }
    ]
  },
  {
    name: 'scp: P2 arn:aws:sqs:us-east-1 rejected',
    policyType: 'scp',
    effect: 'Deny',
    resourceStatements: ['arn:aws:sqs:us-east-1'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [
      {
        resource: 'arn:aws:sqs:us-east-1',
        matches: false,
        errors: ['Policy resource ARN is not valid for this policy type']
      }
    ]
  },
  {
    name: 'scp: P3 arn:aws:sqs:us-east-1:111111111111 rejected',
    policyType: 'scp',
    effect: 'Deny',
    resourceStatements: ['arn:aws:sqs:us-east-1:111111111111'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [
      {
        resource: 'arn:aws:sqs:us-east-1:111111111111',
        matches: false,
        errors: ['Policy resource ARN is not valid for this policy type']
      }
    ]
  },
  {
    name: 'scp: P4 arn:aws:sqs:* matches Q as deny',
    policyType: 'scp',
    effect: 'Deny',
    resourceStatements: ['arn:aws:sqs:*'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: true,
    explains: [{ resource: 'arn:aws:sqs:*', matches: true }]
  },
  {
    name: 'scp: P5 arn:aws:sqs:us-east-1:* matches Q as deny',
    policyType: 'scp',
    effect: 'Deny',
    resourceStatements: ['arn:aws:sqs:us-east-1:*'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: true,
    explains: [{ resource: 'arn:aws:sqs:us-east-1:*', matches: true }]
  },
  {
    name: 'scp: P6 arn:aws:sqs:us-east-1:111111111111:* matches Q as deny',
    policyType: 'scp',
    effect: 'Deny',
    resourceStatements: ['arn:aws:sqs:us-east-1:111111111111:*'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: true,
    explains: [{ resource: 'arn:aws:sqs:us-east-1:111111111111:*', matches: true }]
  },
  {
    name: 'scp: P7 arn:aws:sqs:us-west-2 rejected',
    policyType: 'scp',
    effect: 'Deny',
    resourceStatements: ['arn:aws:sqs:us-west-2'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [
      {
        resource: 'arn:aws:sqs:us-west-2',
        matches: false,
        errors: ['Policy resource ARN is not valid for this policy type']
      }
    ]
  },
  {
    name: 'scp: P8 arn:aws:sqs:us-east-1:222222222222 rejected',
    policyType: 'scp',
    effect: 'Deny',
    resourceStatements: ['arn:aws:sqs:us-east-1:222222222222'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [
      {
        resource: 'arn:aws:sqs:us-east-1:222222222222',
        matches: false,
        errors: ['Policy resource ARN is not valid for this policy type']
      }
    ]
  },
  {
    name: 'scp: P9 arn:aws:sqs:us-east-1:111111111111:other-queue does not match Q',
    policyType: 'scp',
    effect: 'Deny',
    resourceStatements: ['arn:aws:sqs:us-east-1:111111111111:other-queue'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [{ resource: 'arn:aws:sqs:us-east-1:111111111111:other-queue', matches: false }]
  },
  {
    name: 'scp: P10 exact match Q as deny',
    policyType: 'scp',
    effect: 'Deny',
    resourceStatements: ['arn:aws:sqs:us-east-1:111111111111:test-queue'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: true,
    explains: [{ resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue', matches: true }]
  },

  // ── Short ARN tests: RCP (Deny) ───────────────────────────────────────
  {
    name: 'rcp: P1 arn:aws:sqs rejected',
    policyType: 'rcp',
    effect: 'Deny',
    resourceStatements: ['arn:aws:sqs'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [
      {
        resource: 'arn:aws:sqs',
        matches: false,
        errors: ['Policy resource ARN is not valid for this policy type']
      }
    ]
  },
  {
    name: 'rcp: P2 arn:aws:sqs:us-east-1 rejected',
    policyType: 'rcp',
    effect: 'Deny',
    resourceStatements: ['arn:aws:sqs:us-east-1'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [
      {
        resource: 'arn:aws:sqs:us-east-1',
        matches: false,
        errors: ['Policy resource ARN is not valid for this policy type']
      }
    ]
  },
  {
    name: 'rcp: P3 arn:aws:sqs:us-east-1:111111111111 rejected',
    policyType: 'rcp',
    effect: 'Deny',
    resourceStatements: ['arn:aws:sqs:us-east-1:111111111111'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [
      {
        resource: 'arn:aws:sqs:us-east-1:111111111111',
        matches: false,
        errors: ['Policy resource ARN is not valid for this policy type']
      }
    ]
  },
  {
    name: 'rcp: P4 arn:aws:sqs:* is not valid for RCP',
    policyType: 'rcp',
    effect: 'Deny',
    resourceStatements: ['arn:aws:sqs:*'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [
      {
        resource: 'arn:aws:sqs:*',
        matches: false,
        errors: ['Policy resource ARN is not valid for this policy type']
      }
    ]
  },
  {
    name: 'rcp: P5 arn:aws:sqs:us-east-1:* is not valid for RCP',
    policyType: 'rcp',
    effect: 'Deny',
    resourceStatements: ['arn:aws:sqs:us-east-1:*'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [
      {
        resource: 'arn:aws:sqs:us-east-1:*',
        matches: false,
        errors: ['Policy resource ARN is not valid for this policy type']
      }
    ]
  },
  {
    name: 'rcp: P6 arn:aws:sqs:us-east-1:111111111111:* matches Q as deny',
    policyType: 'rcp',
    effect: 'Deny',
    resourceStatements: ['arn:aws:sqs:us-east-1:111111111111:*'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: true,
    explains: [{ resource: 'arn:aws:sqs:us-east-1:111111111111:*', matches: true }]
  },
  {
    name: 'rcp: P7 arn:aws:sqs:us-west-2 is not valid for RCP',
    policyType: 'rcp',
    effect: 'Deny',
    resourceStatements: ['arn:aws:sqs:us-west-2'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [
      {
        resource: 'arn:aws:sqs:us-west-2',
        matches: false,
        errors: ['Policy resource ARN is not valid for this policy type']
      }
    ]
  },
  {
    name: 'rcp: P8 arn:aws:sqs:us-east-1:222222222222 is not valid for RCP',
    policyType: 'rcp',
    effect: 'Deny',
    resourceStatements: ['arn:aws:sqs:us-east-1:222222222222'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [
      {
        resource: 'arn:aws:sqs:us-east-1:222222222222',
        matches: false,
        errors: ['Policy resource ARN is not valid for this policy type']
      }
    ]
  },
  {
    name: 'rcp: P9 arn:aws:sqs:us-east-1:111111111111:other-queue does not match Q',
    policyType: 'rcp',
    effect: 'Deny',
    resourceStatements: ['arn:aws:sqs:us-east-1:111111111111:other-queue'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [{ resource: 'arn:aws:sqs:us-east-1:111111111111:other-queue', matches: false }]
  },
  {
    name: 'rcp: P10 exact match Q as deny',
    policyType: 'rcp',
    effect: 'Deny',
    resourceStatements: ['arn:aws:sqs:us-east-1:111111111111:test-queue'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: true,
    explains: [{ resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue', matches: true }]
  },

  // ── Short ARN negative tests: expanded but explicit segments mismatch ──────
  // Request: arn:aws:sqs:us-east-2:111111111111:MyQueue
  {
    name: 'identity: short ARN region mismatch after expansion (4 seg)',
    policyType: 'identity',
    resourceStatements: ['arn:aws:sqs:us-east-1'],
    resource: {
      resource: 'arn:aws:sqs:us-east-2:111111111111:MyQueue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [
      { resource: 'arn:aws:sqs:us-east-1', matches: false, errors: ['Region does not match'] }
    ]
  },
  {
    name: 'identity: short ARN account mismatch after expansion (5 seg)',
    policyType: 'identity',
    resourceStatements: ['arn:aws:sqs:us-east-2:222222222222'],
    resource: {
      resource: 'arn:aws:sqs:us-east-2:111111111111:MyQueue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [
      {
        resource: 'arn:aws:sqs:us-east-2:222222222222',
        matches: false,
        errors: ['Account does not match']
      }
    ]
  },
  {
    name: 'identity: short ARN service mismatch after expansion (3 seg)',
    policyType: 'identity',
    resourceStatements: ['arn:aws:ec2'],
    resource: {
      resource: 'arn:aws:sqs:us-east-2:111111111111:MyQueue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [{ resource: 'arn:aws:ec2', matches: false, errors: ['Service does not match'] }]
  },
  {
    name: 'identity: short ARN with wildcard region mismatch in account (5 seg)',
    policyType: 'identity',
    resourceStatements: ['arn:aws:sqs:*:222222222222'],
    resource: {
      resource: 'arn:aws:sqs:us-east-2:111111111111:MyQueue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [
      { resource: 'arn:aws:sqs:*:222222222222', matches: false, errors: ['Account does not match'] }
    ]
  },
  {
    name: 'resource: short ARN with wildcard region mismatch in account (5 seg)',
    policyType: 'resource',
    resourceStatements: ['arn:aws:sqs:*:222222222222'],
    resource: {
      resource: 'arn:aws:sqs:us-east-2:111111111111:MyQueue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [
      { resource: 'arn:aws:sqs:*:222222222222', matches: false, errors: ['Account does not match'] }
    ]
  },
  {
    name: 'scp: short ARN with wildcard in middle rejected (5 seg, deny)',
    policyType: 'scp',
    effect: 'Deny',
    resourceStatements: ['arn:aws:sqs:*:222222222222'],
    resource: {
      resource: 'arn:aws:sqs:us-east-2:111111111111:MyQueue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [
      {
        resource: 'arn:aws:sqs:*:222222222222',
        matches: false,
        errors: ['Policy resource ARN is not valid for this policy type']
      }
    ]
  },
  {
    name: 'resource: short ARN without wildcard does not expand (4 seg, region mismatch)',
    policyType: 'resource',
    resourceStatements: ['arn:aws:sqs:us-east-1'],
    resource: {
      resource: 'arn:aws:sqs:us-east-2:111111111111:MyQueue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [{ resource: 'arn:aws:sqs:us-east-1', matches: false }]
  },
  {
    name: 'resource: short ARN without wildcard does not expand (5 seg, account mismatch)',
    policyType: 'resource',
    resourceStatements: ['arn:aws:sqs:us-east-2:222222222222'],
    resource: {
      resource: 'arn:aws:sqs:us-east-2:111111111111:MyQueue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [{ resource: 'arn:aws:sqs:us-east-2:222222222222', matches: false }]
  },

  // ── Middle-wildcard tests: PM1 arn:aws:sqs:*:111111111111 (5 seg, wildcard in region) ──
  {
    name: 'identity: PM1 arn:aws:sqs:*:111111111111 matches Q (wildcard in middle)',
    policyType: 'identity',
    resourceStatements: ['arn:aws:sqs:*:111111111111'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: true,
    explains: [{ resource: 'arn:aws:sqs:*:111111111111', matches: true }]
  },
  {
    name: 'session: PM1 arn:aws:sqs:*:111111111111 matches Q (wildcard in middle)',
    policyType: 'session',
    resourceStatements: ['arn:aws:sqs:*:111111111111'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: true,
    explains: [{ resource: 'arn:aws:sqs:*:111111111111', matches: true }]
  },
  {
    name: 'pb: PM1 arn:aws:sqs:*:111111111111 matches Q (wildcard in middle)',
    policyType: 'pb',
    resourceStatements: ['arn:aws:sqs:*:111111111111'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: true,
    explains: [{ resource: 'arn:aws:sqs:*:111111111111', matches: true }]
  },
  {
    name: 'resource: PM1 arn:aws:sqs:*:111111111111 matches Q (wildcard in middle)',
    policyType: 'resource',
    resourceStatements: ['arn:aws:sqs:*:111111111111'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: true,
    explains: [{ resource: 'arn:aws:sqs:*:111111111111', matches: true }]
  },
  {
    name: 'vpce: PM1 arn:aws:sqs:*:111111111111 matches Q (wildcard in middle)',
    policyType: 'vpce',
    resourceStatements: ['arn:aws:sqs:*:111111111111'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: true,
    explains: [{ resource: 'arn:aws:sqs:*:111111111111', matches: true }]
  },
  {
    name: 'scp: PM1 arn:aws:sqs:*:111111111111 rejected (wildcard in middle, not at end)',
    policyType: 'scp',
    effect: 'Deny',
    resourceStatements: ['arn:aws:sqs:*:111111111111'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [
      {
        resource: 'arn:aws:sqs:*:111111111111',
        matches: false,
        errors: ['Policy resource ARN is not valid for this policy type']
      }
    ]
  },
  {
    name: 'rcp: PM1 arn:aws:sqs:*:111111111111 rejected (wildcard in middle)',
    policyType: 'rcp',
    effect: 'Deny',
    resourceStatements: ['arn:aws:sqs:*:111111111111'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [
      {
        resource: 'arn:aws:sqs:*:111111111111',
        matches: false,
        errors: ['Policy resource ARN is not valid for this policy type']
      }
    ]
  },

  // ── Middle-wildcard tests: PM2 arn:aws:sqs:*:111111111111:test-queue (6 seg, full ARN) ──
  {
    name: 'identity: PM2 arn:aws:sqs:*:111111111111:test-queue matches Q (full ARN, wildcard in region)',
    policyType: 'identity',
    resourceStatements: ['arn:aws:sqs:*:111111111111:test-queue'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: true,
    explains: [{ resource: 'arn:aws:sqs:*:111111111111:test-queue', matches: true }]
  },
  {
    name: 'session: PM2 arn:aws:sqs:*:111111111111:test-queue matches Q (full ARN, wildcard in region)',
    policyType: 'session',
    resourceStatements: ['arn:aws:sqs:*:111111111111:test-queue'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: true,
    explains: [{ resource: 'arn:aws:sqs:*:111111111111:test-queue', matches: true }]
  },
  {
    name: 'pb: PM2 arn:aws:sqs:*:111111111111:test-queue matches Q (full ARN, wildcard in region)',
    policyType: 'pb',
    resourceStatements: ['arn:aws:sqs:*:111111111111:test-queue'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: true,
    explains: [{ resource: 'arn:aws:sqs:*:111111111111:test-queue', matches: true }]
  },
  {
    name: 'resource: PM2 arn:aws:sqs:*:111111111111:test-queue matches Q (full ARN, wildcard in region)',
    policyType: 'resource',
    resourceStatements: ['arn:aws:sqs:*:111111111111:test-queue'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: true,
    explains: [{ resource: 'arn:aws:sqs:*:111111111111:test-queue', matches: true }]
  },
  {
    name: 'vpce: PM2 arn:aws:sqs:*:111111111111:test-queue matches Q (full ARN, wildcard in region)',
    policyType: 'vpce',
    resourceStatements: ['arn:aws:sqs:*:111111111111:test-queue'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: true,
    explains: [{ resource: 'arn:aws:sqs:*:111111111111:test-queue', matches: true }]
  },
  {
    name: 'scp: PM2 arn:aws:sqs:*:111111111111:test-queue matches Q as deny (full ARN, wildcard in region)',
    policyType: 'scp',
    effect: 'Deny',
    resourceStatements: ['arn:aws:sqs:*:111111111111:test-queue'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: true,
    explains: [{ resource: 'arn:aws:sqs:*:111111111111:test-queue', matches: true }]
  },
  {
    name: 'rcp: PM2 arn:aws:sqs:*:111111111111:test-queue matches Q as deny (full ARN, wildcard in region)',
    policyType: 'rcp',
    effect: 'Deny',
    resourceStatements: ['arn:aws:sqs:*:111111111111:test-queue'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: true,
    explains: [{ resource: 'arn:aws:sqs:*:111111111111:test-queue', matches: true }]
  }
]

function validateExplains(expected: ResourceExplain[], actual: ResourceExplain[]) {
  expect(actual.length).toBe(expected.length)
  for (const explain of expected) {
    const found = actual.find((e) => e.resource === explain.resource)
    expect(found, `Missing explain for ${explain.resource}`).toBeDefined()
    expect(found?.matches, `${explain.resource} match`).toBe(explain.matches)
    if (explain.resolvedValue) {
      expect(found?.resolvedValue, `${explain.resource} resolved value`).toBe(explain.resolvedValue)
    } else {
      expect(
        found?.resolvedValue,
        `${explain.resource} resolved value to be undefined`
      ).toBeUndefined()
    }
    if (explain.errors) {
      expect(found?.errors, `${explain.resource} errors`).toEqual(explain.errors.sort())
    } else {
      expect(found?.errors, `${explain.resource} errors`).toBeUndefined()
    }
    if (explain.mismatchReason) {
      expect(found?.mismatchReason, `${explain.resource} mismatch reason`).toBe(
        explain.mismatchReason
      )
    }
  }
}

describe('resourcePatternOverlap', () => {
  it('should treat leading question marks in policy patterns as IAM wildcards instead of regex quantifiers', () => {
    //Given a policy resource pattern that starts with question mark wildcards
    const policyResource = '??-example-bucket/data/v1/*/_logs/*'
    const wildcardRequestResource = 'ab-example-bucket/data/v1/table/_logs/*'

    //When the resource patterns are compared for overlap
    const result = resourcePatternOverlap(policyResource, wildcardRequestResource)

    //Then the policy pattern should be detected as a superset without throwing a SyntaxError
    expect(result).toBe('policy_is_superset')
  })

  it('should detect non-empty intersections where neither wildcard pattern contains the other', () => {
    //Given policy and request resource patterns that overlap on some concrete resources
    const policyResource = 'arn:aws:s3:::example-bucket/*'
    const wildcardRequestResource = 'arn:aws:s3:::*/AWSLogs/*'

    //When the resource patterns are compared for overlap
    const result = resourcePatternOverlap(policyResource, wildcardRequestResource)

    //Then the partial intersection should be detected
    expect(result).toBe('overlap')
  })

  it('should treat question marks in request patterns as literals instead of regex quantifiers', () => {
    //Given a wildcard request resource that contains literal question marks
    const policyResource = 'ab-example-bucket/data/v1/table/_logs/object.json'
    const wildcardRequestResource = '??-example-bucket/data/v1/*/_logs/*'

    //When the resource patterns are compared for overlap
    const result = resourcePatternOverlap(policyResource, wildcardRequestResource)

    //Then unsupported request question marks should not create an invalid regular expression
    expect(result).toBe('none')
  })
})

describe('requestMatchesResources', () => {
  for (const rt of resourceTests) {
    const testFn = rt.only ? it.only : it
    testFn(rt.name || `should match ${rt.resource}`, () => {
      //Given a policy
      const policy = loadPolicy({
        Statement: {
          Effect: rt.effect ?? 'Allow',
          Resource: rt.resourceStatements
        }
      })

      //And a request with a resource
      const request = new AwsRequestImpl(
        'principal',
        rt.resource,
        's3:GetBucket',
        new RequestContextImpl(rt.context || {}),
        rt.wildcardOnlyAction
      )

      //When the request is checked against the resource statement
      const response = requestMatchesResources(
        request,
        (policy.statements()[0] as ResourceStatement).resources(),
        rt.resourceStatements ? 'Resource' : 'NotResource',
        rt.effect ?? 'Allow',
        rt.policyType ?? 'identity'
      )

      //Then the request should match the resource statement
      expect(response.matches).toBe(rt.expectMatch)
      validateExplains(rt.explains, response.explains)
    })
  }
})

const notResourceTests: ResourceTest[] = [
  {
    name: 'should match a different resource',
    notResourceStatements: ['arn:aws:s3:::my_corporate_bucket'],
    resource: {
      resource: 'arn:aws:s3:::different_bucket',
      accountId: '123456789012'
    },
    expectMatch: true,
    explains: [
      {
        resource: 'arn:aws:s3:::my_corporate_bucket',
        matches: true
      }
    ]
  },
  {
    name: 'should not match if any resource matches',
    notResourceStatements: ['arn:aws:s3:::my_corporate_bucket', 'arn:aws:s3:::different_bucket'],
    resource: {
      resource: 'arn:aws:s3:::different_bucket',
      accountId: '123456789012'
    },
    expectMatch: false,
    explains: [
      {
        resource: 'arn:aws:s3:::my_corporate_bucket',
        matches: true
      },
      {
        resource: 'arn:aws:s3:::different_bucket',
        matches: false
      }
    ]
  },
  {
    name: 'should match if all resources do not match',
    notResourceStatements: ['arn:aws:s3:::my_corporate_bucket', 'arn:aws:s3:::different_bucket'],
    resource: {
      resource: 'arn:aws:s3:::yet_another_bucket',
      accountId: '123456789012'
    },
    expectMatch: true,
    explains: [
      {
        resource: 'arn:aws:s3:::my_corporate_bucket',
        matches: true
      },
      {
        resource: 'arn:aws:s3:::different_bucket',
        matches: true
      }
    ]
  },
  {
    name: 'SCP Deny NotResource should match a request for a different service full ARN',
    policyType: 'scp',
    effect: 'Deny',
    notResourceStatements: ['arn:aws:iam::aws:policy/*'],
    resource: {
      resource: 'arn:aws:s3:::example-bucket/example-object.txt',
      accountId: '123456789012'
    },
    expectMatch: true,
    explains: [
      {
        resource: 'arn:aws:iam::aws:policy/*',
        matches: true
      }
    ]
  },
  {
    name: 'should not match if a variable is missing',
    notResourceStatements: ['arn:aws:ec2:us-east-1:123456789012:instance/${aws:PrincipalTag/Foo}'],
    resource: {
      resource: 'arn:aws:ec2:us-east-1:123456789012:instance/bar',
      accountId: '123456789012'
    },
    expectMatch: false,
    explains: [
      {
        resource: 'arn:aws:ec2:us-east-1:123456789012:instance/${aws:PrincipalTag/Foo}',
        matches: false,
        errors: [
          '{aws:PrincipalTag/Foo} not found in request context, and no default value provided. This will never match'
        ]
      }
    ]
  },
  {
    name: 'NotResource & Allow when policy is a superset of a request wildcard',
    notResourceStatements: ['arn:aws:s3:::my_corporate_bucket/*'],
    effect: 'Allow',
    resource: {
      resource: 'arn:aws:s3:::my_corporate_bucket/foo*',
      accountId: '123456789012'
    },
    expectMatch: false,
    explains: [
      {
        resource: 'arn:aws:s3:::my_corporate_bucket/*',
        matches: false
      }
    ]
  },
  {
    name: 'NotResource & Allow when policy is a subset of a request wildcard',
    notResourceStatements: ['arn:aws:s3:::my_corporate_bucket/foo*'],
    effect: 'Allow',
    resource: {
      resource: 'arn:aws:s3:::my_corporate_bucket/*',
      accountId: '123456789012'
    },
    expectMatch: true,
    explains: [
      {
        resource: 'arn:aws:s3:::my_corporate_bucket/foo*',
        matches: true
      }
    ]
  },
  {
    name: 'NotResource & Allow when policy and request wildcards do not overlap',
    notResourceStatements: ['arn:aws:s3:::my_corporate_bucket/bar*'],
    effect: 'Allow',
    resource: {
      resource: 'arn:aws:s3:::my_corporate_bucket/foo*',
      accountId: '123456789012'
    },
    expectMatch: true,
    explains: [
      {
        resource: 'arn:aws:s3:::my_corporate_bucket/bar*',
        matches: true
      }
    ]
  },
  {
    name: 'NotResource & Allow when request is a single wildcard',
    notResourceStatements: ['arn:aws:s3:::my_corporate_bucket'],
    effect: 'Allow',
    resource: {
      resource: '*',
      accountId: '123456789012'
    },
    expectMatch: true,
    explains: [
      {
        resource: 'arn:aws:s3:::my_corporate_bucket',
        matches: true
      }
    ]
  },
  {
    name: 'NotResource & Allow when policy and request wildcards are identical',
    notResourceStatements: ['arn:aws:s3:::my_corporate_bucket/*'],
    effect: 'Allow',
    resource: {
      resource: 'arn:aws:s3:::my_corporate_bucket/*',
      accountId: '123456789012'
    },
    expectMatch: false,
    explains: [
      {
        resource: 'arn:aws:s3:::my_corporate_bucket/*',
        matches: false
      }
    ]
  },
  {
    name: 'NotResource & Allow when policy and request wildcards are identical in a non-resource segment',
    notResourceStatements: ['arn:aws:ec2:*:123456789012:instance/*'],
    effect: 'Allow',
    resource: {
      resource: 'arn:aws:ec2:*:123456789012:instance/*',
      accountId: '123456789012'
    },
    expectMatch: false,
    explains: [
      {
        resource: 'arn:aws:ec2:*:123456789012:instance/*',
        matches: false
      }
    ]
  },
  {
    name: 'NotResource & Deny when policy and request wildcards are identical for deny',
    notResourceStatements: ['arn:aws:s3:::my_corporate_bucket/*'],
    effect: 'Deny',
    resource: {
      resource: 'arn:aws:s3:::my_corporate_bucket/*',
      accountId: '123456789012'
    },
    expectMatch: false,
    explains: [
      {
        resource: 'arn:aws:s3:::my_corporate_bucket/*',
        matches: false
      }
    ]
  },
  {
    name: 'NotResource & Deny when policy and request wildcards are identical in a non-resource segment for deny',
    notResourceStatements: ['arn:aws:ec2:*:123456789012:instance/*'],
    effect: 'Deny',
    resource: {
      resource: 'arn:aws:ec2:*:123456789012:instance/*',
      accountId: '123456789012'
    },
    expectMatch: false,
    explains: [
      {
        resource: 'arn:aws:ec2:*:123456789012:instance/*',
        matches: false
      }
    ]
  },
  {
    name: 'NotResource & Deny when policy is a subset of a request wildcard for deny',
    notResourceStatements: ['arn:aws:s3:::my_corporate_bucket/foo*'],
    effect: 'Deny',
    resource: {
      resource: 'arn:aws:s3:::my_corporate_bucket/*',
      accountId: '123456789012'
    },
    expectMatch: false,
    explains: [
      {
        resource: 'arn:aws:s3:::my_corporate_bucket/foo*',
        matches: false
      }
    ]
  },
  {
    name: 'NotResource & Deny when request wildcard is in a non-resource segment for deny',
    notResourceStatements: ['arn:aws:ec2:us-east-1:123456789012:instance/i-123'],
    effect: 'Deny',
    resource: {
      resource: 'arn:aws:ec2:*:123456789012:instance/i-123',
      accountId: '123456789012'
    },
    expectMatch: false,
    explains: [
      {
        resource: 'arn:aws:ec2:us-east-1:123456789012:instance/i-123',
        matches: false
      }
    ]
  },
  {
    name: 'NotResource & Deny when policy is a superset of a request wildcard for deny',
    notResourceStatements: ['arn:aws:s3:::my_corporate_bucket/*'],
    effect: 'Deny',
    resource: {
      resource: 'arn:aws:s3:::my_corporate_bucket/foo*',
      accountId: '123456789012'
    },
    expectMatch: false,
    explains: [
      {
        resource: 'arn:aws:s3:::my_corporate_bucket/*',
        matches: false
      }
    ]
  },
  {
    name: 'NotResource & Deny when policy and request wildcards do not overlap for deny',
    notResourceStatements: ['arn:aws:s3:::my_corporate_bucket/bar*'],
    effect: 'Deny',
    resource: {
      resource: 'arn:aws:s3:::my_corporate_bucket/foo*',
      accountId: '123456789012'
    },
    expectMatch: true,
    explains: [
      {
        resource: 'arn:aws:s3:::my_corporate_bucket/bar*',
        matches: true
      }
    ]
  },
  {
    name: 'wildcard-only action: should match Allow/NotResource with specific ARN',
    notResourceStatements: ['arn:aws:s3:::my-bucket'],
    wildcardOnlyAction: true,
    resource: {
      resource: '*',
      accountId: '123456789012'
    },
    expectMatch: true,
    explains: [
      {
        resource: 'arn:aws:s3:::my-bucket',
        matches: true
      }
    ]
  },
  {
    name: 'wildcard-only action: should not match Allow/NotResource with * resource',
    notResourceStatements: ['*'],
    wildcardOnlyAction: true,
    resource: {
      resource: '*',
      accountId: '123456789012'
    },
    expectMatch: false,
    explains: [
      {
        resource: '*',
        matches: false
      }
    ]
  },
  {
    name: 'wildcard-only action: should match Deny/NotResource with specific ARN',
    notResourceStatements: ['arn:aws:s3:::my-bucket'],
    effect: 'Deny',
    wildcardOnlyAction: true,
    resource: {
      resource: '*',
      accountId: '123456789012'
    },
    expectMatch: true,
    explains: [
      {
        resource: 'arn:aws:s3:::my-bucket',
        matches: true
      }
    ]
  },
  {
    name: 'wildcard-only action: should not match Deny/NotResource with * resource',
    notResourceStatements: ['*'],
    effect: 'Deny',
    wildcardOnlyAction: true,
    resource: {
      resource: '*',
      accountId: '123456789012'
    },
    expectMatch: false,
    explains: [
      {
        resource: '*',
        matches: false
      }
    ]
  },

  // ── Short ARN tests: Identity Policy NotResource (Allow) ──────────────
  {
    name: 'identity NotResource: P1 arn:aws:sqs does not match Q (inverted from match)',
    policyType: 'identity',
    notResourceStatements: ['arn:aws:sqs'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [{ resource: 'arn:aws:sqs', matches: false }]
  },
  {
    name: 'identity NotResource: P2 arn:aws:sqs:us-east-1 does not match Q (inverted from match)',
    policyType: 'identity',
    notResourceStatements: ['arn:aws:sqs:us-east-1'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [{ resource: 'arn:aws:sqs:us-east-1', matches: false }]
  },
  {
    name: 'identity NotResource: P3 arn:aws:sqs:us-east-1:111111111111 does not match Q (inverted from match)',
    policyType: 'identity',
    notResourceStatements: ['arn:aws:sqs:us-east-1:111111111111'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [{ resource: 'arn:aws:sqs:us-east-1:111111111111', matches: false }]
  },
  {
    name: 'identity NotResource: P4 arn:aws:sqs:* does not match Q (inverted from match)',
    policyType: 'identity',
    notResourceStatements: ['arn:aws:sqs:*'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [{ resource: 'arn:aws:sqs:*', matches: false }]
  },
  {
    name: 'identity NotResource: P5 arn:aws:sqs:us-east-1:* does not match Q (inverted from match)',
    policyType: 'identity',
    notResourceStatements: ['arn:aws:sqs:us-east-1:*'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [{ resource: 'arn:aws:sqs:us-east-1:*', matches: false }]
  },
  {
    name: 'identity NotResource: P6 arn:aws:sqs:us-east-1:111111111111:* does not match Q (inverted from match)',
    policyType: 'identity',
    notResourceStatements: ['arn:aws:sqs:us-east-1:111111111111:*'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [{ resource: 'arn:aws:sqs:us-east-1:111111111111:*', matches: false }]
  },
  {
    name: 'identity NotResource: P7 arn:aws:sqs:us-west-2 does not match Q (expanded, region mismatch)',
    policyType: 'identity',
    notResourceStatements: ['arn:aws:sqs:us-west-2'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [
      { resource: 'arn:aws:sqs:us-west-2', matches: false, errors: ['Region does not match'] }
    ]
  },
  {
    name: 'identity NotResource: P8 arn:aws:sqs:us-east-1:222222222222 does not match Q (expanded, account mismatch)',
    policyType: 'identity',
    notResourceStatements: ['arn:aws:sqs:us-east-1:222222222222'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [
      {
        resource: 'arn:aws:sqs:us-east-1:222222222222',
        matches: false,
        errors: ['Account does not match']
      }
    ]
  },
  {
    name: 'identity NotResource: P9 arn:aws:sqs:us-east-1:111111111111:other-queue matches Q (inverted from no match)',
    policyType: 'identity',
    notResourceStatements: ['arn:aws:sqs:us-east-1:111111111111:other-queue'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: true,
    explains: [{ resource: 'arn:aws:sqs:us-east-1:111111111111:other-queue', matches: true }]
  },
  {
    name: 'identity NotResource: P10 exact match Q does not match (inverted from match)',
    policyType: 'identity',
    notResourceStatements: ['arn:aws:sqs:us-east-1:111111111111:test-queue'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [{ resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue', matches: false }]
  },

  // ── Short ARN tests: Session Policy NotResource (Allow) ───────────────
  {
    name: 'session NotResource: P1 arn:aws:sqs does not match Q (inverted from match)',
    policyType: 'session',
    notResourceStatements: ['arn:aws:sqs'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [{ resource: 'arn:aws:sqs', matches: false }]
  },
  {
    name: 'session NotResource: P2 arn:aws:sqs:us-east-1 does not match Q (inverted from match)',
    policyType: 'session',
    notResourceStatements: ['arn:aws:sqs:us-east-1'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [{ resource: 'arn:aws:sqs:us-east-1', matches: false }]
  },
  {
    name: 'session NotResource: P3 arn:aws:sqs:us-east-1:111111111111 does not match Q (inverted from match)',
    policyType: 'session',
    notResourceStatements: ['arn:aws:sqs:us-east-1:111111111111'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [{ resource: 'arn:aws:sqs:us-east-1:111111111111', matches: false }]
  },
  {
    name: 'session NotResource: P4 arn:aws:sqs:* does not match Q (inverted from match)',
    policyType: 'session',
    notResourceStatements: ['arn:aws:sqs:*'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [{ resource: 'arn:aws:sqs:*', matches: false }]
  },
  {
    name: 'session NotResource: P5 arn:aws:sqs:us-east-1:* does not match Q (inverted from match)',
    policyType: 'session',
    notResourceStatements: ['arn:aws:sqs:us-east-1:*'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [{ resource: 'arn:aws:sqs:us-east-1:*', matches: false }]
  },
  {
    name: 'session NotResource: P6 arn:aws:sqs:us-east-1:111111111111:* does not match Q (inverted from match)',
    policyType: 'session',
    notResourceStatements: ['arn:aws:sqs:us-east-1:111111111111:*'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [{ resource: 'arn:aws:sqs:us-east-1:111111111111:*', matches: false }]
  },
  {
    name: 'session NotResource: P7 arn:aws:sqs:us-west-2 does not match Q (expanded, region mismatch)',
    policyType: 'session',
    notResourceStatements: ['arn:aws:sqs:us-west-2'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [
      { resource: 'arn:aws:sqs:us-west-2', matches: false, errors: ['Region does not match'] }
    ]
  },
  {
    name: 'session NotResource: P8 arn:aws:sqs:us-east-1:222222222222 does not match Q (expanded, account mismatch)',
    policyType: 'session',
    notResourceStatements: ['arn:aws:sqs:us-east-1:222222222222'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [
      {
        resource: 'arn:aws:sqs:us-east-1:222222222222',
        matches: false,
        errors: ['Account does not match']
      }
    ]
  },
  {
    name: 'session NotResource: P9 arn:aws:sqs:us-east-1:111111111111:other-queue matches Q (inverted from no match)',
    policyType: 'session',
    notResourceStatements: ['arn:aws:sqs:us-east-1:111111111111:other-queue'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: true,
    explains: [{ resource: 'arn:aws:sqs:us-east-1:111111111111:other-queue', matches: true }]
  },
  {
    name: 'session NotResource: P10 exact match Q does not match (inverted from match)',
    policyType: 'session',
    notResourceStatements: ['arn:aws:sqs:us-east-1:111111111111:test-queue'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [{ resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue', matches: false }]
  },

  // ── Short ARN tests: Permission Boundary NotResource (Allow) ──────────
  {
    name: 'pb NotResource: P1 arn:aws:sqs does not match Q (inverted from match)',
    policyType: 'pb',
    notResourceStatements: ['arn:aws:sqs'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [{ resource: 'arn:aws:sqs', matches: false }]
  },
  {
    name: 'pb NotResource: P2 arn:aws:sqs:us-east-1 does not match Q (inverted from match)',
    policyType: 'pb',
    notResourceStatements: ['arn:aws:sqs:us-east-1'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [{ resource: 'arn:aws:sqs:us-east-1', matches: false }]
  },
  {
    name: 'pb NotResource: P3 arn:aws:sqs:us-east-1:111111111111 does not match Q (inverted from match)',
    policyType: 'pb',
    notResourceStatements: ['arn:aws:sqs:us-east-1:111111111111'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [{ resource: 'arn:aws:sqs:us-east-1:111111111111', matches: false }]
  },
  {
    name: 'pb NotResource: P4 arn:aws:sqs:* does not match Q (inverted from match)',
    policyType: 'pb',
    notResourceStatements: ['arn:aws:sqs:*'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [{ resource: 'arn:aws:sqs:*', matches: false }]
  },
  {
    name: 'pb NotResource: P5 arn:aws:sqs:us-east-1:* does not match Q (inverted from match)',
    policyType: 'pb',
    notResourceStatements: ['arn:aws:sqs:us-east-1:*'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [{ resource: 'arn:aws:sqs:us-east-1:*', matches: false }]
  },
  {
    name: 'pb NotResource: P6 arn:aws:sqs:us-east-1:111111111111:* does not match Q (inverted from match)',
    policyType: 'pb',
    notResourceStatements: ['arn:aws:sqs:us-east-1:111111111111:*'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [{ resource: 'arn:aws:sqs:us-east-1:111111111111:*', matches: false }]
  },
  {
    name: 'pb NotResource: P7 arn:aws:sqs:us-west-2 does not match Q (expanded, region mismatch)',
    policyType: 'pb',
    notResourceStatements: ['arn:aws:sqs:us-west-2'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [
      { resource: 'arn:aws:sqs:us-west-2', matches: false, errors: ['Region does not match'] }
    ]
  },
  {
    name: 'pb NotResource: P8 arn:aws:sqs:us-east-1:222222222222 does not match Q (expanded, account mismatch)',
    policyType: 'pb',
    notResourceStatements: ['arn:aws:sqs:us-east-1:222222222222'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [
      {
        resource: 'arn:aws:sqs:us-east-1:222222222222',
        matches: false,
        errors: ['Account does not match']
      }
    ]
  },
  {
    name: 'pb NotResource: P9 arn:aws:sqs:us-east-1:111111111111:other-queue matches Q (inverted from no match)',
    policyType: 'pb',
    notResourceStatements: ['arn:aws:sqs:us-east-1:111111111111:other-queue'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: true,
    explains: [{ resource: 'arn:aws:sqs:us-east-1:111111111111:other-queue', matches: true }]
  },
  {
    name: 'pb NotResource: P10 exact match Q does not match (inverted from match)',
    policyType: 'pb',
    notResourceStatements: ['arn:aws:sqs:us-east-1:111111111111:test-queue'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [{ resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue', matches: false }]
  },

  // ── Short ARN tests: Resource Policy NotResource (Allow) ──────────────
  {
    name: 'resource NotResource: P1 arn:aws:sqs matches Q (inverted from no match)',
    policyType: 'resource',
    notResourceStatements: ['arn:aws:sqs'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: true,
    explains: [{ resource: 'arn:aws:sqs', matches: true }]
  },
  {
    name: 'resource NotResource: P2 arn:aws:sqs:us-east-1 matches Q (inverted from no match)',
    policyType: 'resource',
    notResourceStatements: ['arn:aws:sqs:us-east-1'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: true,
    explains: [{ resource: 'arn:aws:sqs:us-east-1', matches: true }]
  },
  {
    name: 'resource NotResource: P3 arn:aws:sqs:us-east-1:111111111111 matches Q (inverted from no match)',
    policyType: 'resource',
    notResourceStatements: ['arn:aws:sqs:us-east-1:111111111111'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: true,
    explains: [{ resource: 'arn:aws:sqs:us-east-1:111111111111', matches: true }]
  },
  {
    name: 'resource NotResource: P4 arn:aws:sqs:* does not match Q (inverted from match)',
    policyType: 'resource',
    notResourceStatements: ['arn:aws:sqs:*'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [{ resource: 'arn:aws:sqs:*', matches: false }]
  },
  {
    name: 'resource NotResource: P5 arn:aws:sqs:us-east-1:* does not match Q (inverted from match)',
    policyType: 'resource',
    notResourceStatements: ['arn:aws:sqs:us-east-1:*'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [{ resource: 'arn:aws:sqs:us-east-1:*', matches: false }]
  },
  {
    name: 'resource NotResource: P6 arn:aws:sqs:us-east-1:111111111111:* does not match Q (inverted from match)',
    policyType: 'resource',
    notResourceStatements: ['arn:aws:sqs:us-east-1:111111111111:*'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [{ resource: 'arn:aws:sqs:us-east-1:111111111111:*', matches: false }]
  },
  {
    name: 'resource NotResource: P7 arn:aws:sqs:us-west-2 matches Q (inverted from no match)',
    policyType: 'resource',
    notResourceStatements: ['arn:aws:sqs:us-west-2'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: true,
    explains: [{ resource: 'arn:aws:sqs:us-west-2', matches: true }]
  },
  {
    name: 'resource NotResource: P8 arn:aws:sqs:us-east-1:222222222222 matches Q (inverted from no match)',
    policyType: 'resource',
    notResourceStatements: ['arn:aws:sqs:us-east-1:222222222222'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: true,
    explains: [{ resource: 'arn:aws:sqs:us-east-1:222222222222', matches: true }]
  },
  {
    name: 'resource NotResource: P9 arn:aws:sqs:us-east-1:111111111111:other-queue matches Q (inverted from no match)',
    policyType: 'resource',
    notResourceStatements: ['arn:aws:sqs:us-east-1:111111111111:other-queue'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: true,
    explains: [{ resource: 'arn:aws:sqs:us-east-1:111111111111:other-queue', matches: true }]
  },
  {
    name: 'resource NotResource: P10 exact match Q does not match (inverted from match)',
    policyType: 'resource',
    notResourceStatements: ['arn:aws:sqs:us-east-1:111111111111:test-queue'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [{ resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue', matches: false }]
  },

  // ── Short ARN tests: SCP NotResource (Deny) ──────────────────────────
  {
    name: 'scp NotResource: P1 arn:aws:sqs rejected (errors not inverted)',
    policyType: 'scp',
    effect: 'Deny',
    notResourceStatements: ['arn:aws:sqs'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [
      {
        resource: 'arn:aws:sqs',
        matches: false,
        errors: ['Policy resource ARN is not valid for this policy type']
      }
    ]
  },
  {
    name: 'scp NotResource: P2 arn:aws:sqs:us-east-1 rejected (errors not inverted)',
    policyType: 'scp',
    effect: 'Deny',
    notResourceStatements: ['arn:aws:sqs:us-east-1'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [
      {
        resource: 'arn:aws:sqs:us-east-1',
        matches: false,
        errors: ['Policy resource ARN is not valid for this policy type']
      }
    ]
  },
  {
    name: 'scp NotResource: P3 arn:aws:sqs:us-east-1:111111111111 rejected (errors not inverted)',
    policyType: 'scp',
    effect: 'Deny',
    notResourceStatements: ['arn:aws:sqs:us-east-1:111111111111'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [
      {
        resource: 'arn:aws:sqs:us-east-1:111111111111',
        matches: false,
        errors: ['Policy resource ARN is not valid for this policy type']
      }
    ]
  },
  {
    name: 'scp NotResource: P4 arn:aws:sqs:* matches Q (inverted from match)',
    policyType: 'scp',
    effect: 'Deny',
    notResourceStatements: ['arn:aws:sqs:*'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [{ resource: 'arn:aws:sqs:*', matches: false }]
  },
  {
    name: 'scp NotResource: P5 arn:aws:sqs:us-east-1:* matches Q (inverted from match)',
    policyType: 'scp',
    effect: 'Deny',
    notResourceStatements: ['arn:aws:sqs:us-east-1:*'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [{ resource: 'arn:aws:sqs:us-east-1:*', matches: false }]
  },
  {
    name: 'scp NotResource: P6 arn:aws:sqs:us-east-1:111111111111:* matches Q (inverted from match)',
    policyType: 'scp',
    effect: 'Deny',
    notResourceStatements: ['arn:aws:sqs:us-east-1:111111111111:*'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [{ resource: 'arn:aws:sqs:us-east-1:111111111111:*', matches: false }]
  },
  {
    name: 'scp NotResource: P7 arn:aws:sqs:us-west-2 rejected (errors not inverted)',
    policyType: 'scp',
    effect: 'Deny',
    notResourceStatements: ['arn:aws:sqs:us-west-2'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [
      {
        resource: 'arn:aws:sqs:us-west-2',
        matches: false,
        errors: ['Policy resource ARN is not valid for this policy type']
      }
    ]
  },
  {
    name: 'scp NotResource: P8 arn:aws:sqs:us-east-1:222222222222 rejected (errors not inverted)',
    policyType: 'scp',
    effect: 'Deny',
    notResourceStatements: ['arn:aws:sqs:us-east-1:222222222222'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [
      {
        resource: 'arn:aws:sqs:us-east-1:222222222222',
        matches: false,
        errors: ['Policy resource ARN is not valid for this policy type']
      }
    ]
  },
  {
    name: 'scp NotResource: P9 arn:aws:sqs:us-east-1:111111111111:other-queue matches Q (inverted from no match)',
    policyType: 'scp',
    effect: 'Deny',
    notResourceStatements: ['arn:aws:sqs:us-east-1:111111111111:other-queue'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: true,
    explains: [{ resource: 'arn:aws:sqs:us-east-1:111111111111:other-queue', matches: true }]
  },
  {
    name: 'scp NotResource: P10 exact match Q does not match (inverted from match)',
    policyType: 'scp',
    effect: 'Deny',
    notResourceStatements: ['arn:aws:sqs:us-east-1:111111111111:test-queue'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [{ resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue', matches: false }]
  },

  // ── Short ARN tests: RCP NotResource (Deny) ──────────────────────────
  {
    name: 'rcp NotResource: P1 arn:aws:sqs rejected (errors not inverted)',
    policyType: 'rcp',
    effect: 'Deny',
    notResourceStatements: ['arn:aws:sqs'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [
      {
        resource: 'arn:aws:sqs',
        matches: false,
        errors: ['Policy resource ARN is not valid for this policy type']
      }
    ]
  },
  {
    name: 'rcp NotResource: P2 arn:aws:sqs:us-east-1 rejected (errors not inverted)',
    policyType: 'rcp',
    effect: 'Deny',
    notResourceStatements: ['arn:aws:sqs:us-east-1'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [
      {
        resource: 'arn:aws:sqs:us-east-1',
        matches: false,
        errors: ['Policy resource ARN is not valid for this policy type']
      }
    ]
  },
  {
    name: 'rcp NotResource: P3 arn:aws:sqs:us-east-1:111111111111 rejected (errors not inverted)',
    policyType: 'rcp',
    effect: 'Deny',
    notResourceStatements: ['arn:aws:sqs:us-east-1:111111111111'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [
      {
        resource: 'arn:aws:sqs:us-east-1:111111111111',
        matches: false,
        errors: ['Policy resource ARN is not valid for this policy type']
      }
    ]
  },
  {
    name: 'rcp NotResource: P4 arn:aws:sqs:* matches Q (inverted from no match)',
    policyType: 'rcp',
    effect: 'Deny',
    notResourceStatements: ['arn:aws:sqs:*'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [
      {
        resource: 'arn:aws:sqs:*',
        matches: false,
        errors: ['Policy resource ARN is not valid for this policy type']
      }
    ]
  },
  {
    name: 'rcp NotResource: P5 arn:aws:sqs:us-east-1:* rejected (errors not inverted)',
    policyType: 'rcp',
    effect: 'Deny',
    notResourceStatements: ['arn:aws:sqs:us-east-1:*'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [
      {
        resource: 'arn:aws:sqs:us-east-1:*',
        matches: false,
        errors: ['Policy resource ARN is not valid for this policy type']
      }
    ]
  },
  {
    name: 'rcp NotResource: P6 arn:aws:sqs:us-east-1:111111111111:* does not match Q (inverted from match)',
    policyType: 'rcp',
    effect: 'Deny',
    notResourceStatements: ['arn:aws:sqs:us-east-1:111111111111:*'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [{ resource: 'arn:aws:sqs:us-east-1:111111111111:*', matches: false }]
  },
  {
    name: 'rcp NotResource: P7 arn:aws:sqs:us-west-2 rejected (errors not inverted)',
    policyType: 'rcp',
    effect: 'Deny',
    notResourceStatements: ['arn:aws:sqs:us-west-2'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [
      {
        resource: 'arn:aws:sqs:us-west-2',
        matches: false,
        errors: ['Policy resource ARN is not valid for this policy type']
      }
    ]
  },
  {
    name: 'rcp NotResource: P8 arn:aws:sqs:us-east-1:222222222222 rejected (errors not inverted)',
    policyType: 'rcp',
    effect: 'Deny',
    notResourceStatements: ['arn:aws:sqs:us-east-1:222222222222'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [
      {
        resource: 'arn:aws:sqs:us-east-1:222222222222',
        matches: false,
        errors: ['Policy resource ARN is not valid for this policy type']
      }
    ]
  },
  {
    name: 'rcp NotResource: P9 arn:aws:sqs:us-east-1:111111111111:other-queue matches Q (inverted from no match)',
    policyType: 'rcp',
    effect: 'Deny',
    notResourceStatements: ['arn:aws:sqs:us-east-1:111111111111:other-queue'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: true,
    explains: [{ resource: 'arn:aws:sqs:us-east-1:111111111111:other-queue', matches: true }]
  },
  {
    name: 'rcp NotResource: P10 exact match Q does not match (inverted from match)',
    policyType: 'rcp',
    effect: 'Deny',
    notResourceStatements: ['arn:aws:sqs:us-east-1:111111111111:test-queue'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [{ resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue', matches: false }]
  },

  // ── Short ARN negative NotResource tests: expanded but explicit segments mismatch ──
  {
    name: 'identity NotResource: short ARN region mismatch after expansion (4 seg, errors not inverted)',
    policyType: 'identity',
    notResourceStatements: ['arn:aws:sqs:us-east-1'],
    resource: {
      resource: 'arn:aws:sqs:us-east-2:111111111111:MyQueue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [
      { resource: 'arn:aws:sqs:us-east-1', matches: false, errors: ['Region does not match'] }
    ]
  },
  {
    name: 'identity NotResource: short ARN account mismatch after expansion (5 seg, errors not inverted)',
    policyType: 'identity',
    notResourceStatements: ['arn:aws:sqs:us-east-2:222222222222'],
    resource: {
      resource: 'arn:aws:sqs:us-east-2:111111111111:MyQueue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [
      {
        resource: 'arn:aws:sqs:us-east-2:222222222222',
        matches: false,
        errors: ['Account does not match']
      }
    ]
  },
  {
    name: 'identity NotResource: short ARN service mismatch after expansion (3 seg, errors not inverted)',
    policyType: 'identity',
    notResourceStatements: ['arn:aws:ec2'],
    resource: {
      resource: 'arn:aws:sqs:us-east-2:111111111111:MyQueue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [{ resource: 'arn:aws:ec2', matches: false, errors: ['Service does not match'] }]
  },
  {
    name: 'identity NotResource: short ARN with wildcard region mismatch in account (5 seg, errors not inverted)',
    policyType: 'identity',
    notResourceStatements: ['arn:aws:sqs:*:222222222222'],
    resource: {
      resource: 'arn:aws:sqs:us-east-2:111111111111:MyQueue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [
      { resource: 'arn:aws:sqs:*:222222222222', matches: false, errors: ['Account does not match'] }
    ]
  },
  {
    name: 'resource NotResource: short ARN with wildcard region mismatch in account (5 seg, errors not inverted)',
    policyType: 'resource',
    notResourceStatements: ['arn:aws:sqs:*:222222222222'],
    resource: {
      resource: 'arn:aws:sqs:us-east-2:111111111111:MyQueue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [
      { resource: 'arn:aws:sqs:*:222222222222', matches: false, errors: ['Account does not match'] }
    ]
  },
  {
    name: 'scp NotResource: short ARN with wildcard in middle rejected (5 seg, errors not inverted)',
    policyType: 'scp',
    effect: 'Deny',
    notResourceStatements: ['arn:aws:sqs:*:222222222222'],
    resource: {
      resource: 'arn:aws:sqs:us-east-2:111111111111:MyQueue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [
      {
        resource: 'arn:aws:sqs:*:222222222222',
        matches: false,
        errors: ['Policy resource ARN is not valid for this policy type']
      }
    ]
  },
  {
    name: 'resource NotResource: short ARN without wildcard does not expand (4 seg, inverted to match)',
    policyType: 'resource',
    notResourceStatements: ['arn:aws:sqs:us-east-1'],
    resource: {
      resource: 'arn:aws:sqs:us-east-2:111111111111:MyQueue',
      accountId: '111111111111'
    },
    expectMatch: true,
    explains: [{ resource: 'arn:aws:sqs:us-east-1', matches: true }]
  },
  {
    name: 'resource NotResource: short ARN without wildcard does not expand (5 seg, inverted to match)',
    policyType: 'resource',
    notResourceStatements: ['arn:aws:sqs:us-east-2:222222222222'],
    resource: {
      resource: 'arn:aws:sqs:us-east-2:111111111111:MyQueue',
      accountId: '111111111111'
    },
    expectMatch: true,
    explains: [{ resource: 'arn:aws:sqs:us-east-2:222222222222', matches: true }]
  },

  // ── Middle-wildcard NotResource tests: PM1 arn:aws:sqs:*:111111111111 (5 seg) ──
  {
    name: 'identity NotResource: PM1 arn:aws:sqs:*:111111111111 does not match Q (inverted from match)',
    policyType: 'identity',
    notResourceStatements: ['arn:aws:sqs:*:111111111111'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [{ resource: 'arn:aws:sqs:*:111111111111', matches: false }]
  },
  {
    name: 'session NotResource: PM1 arn:aws:sqs:*:111111111111 does not match Q (inverted from match)',
    policyType: 'session',
    notResourceStatements: ['arn:aws:sqs:*:111111111111'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [{ resource: 'arn:aws:sqs:*:111111111111', matches: false }]
  },
  {
    name: 'pb NotResource: PM1 arn:aws:sqs:*:111111111111 does not match Q (inverted from match)',
    policyType: 'pb',
    notResourceStatements: ['arn:aws:sqs:*:111111111111'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [{ resource: 'arn:aws:sqs:*:111111111111', matches: false }]
  },
  {
    name: 'resource NotResource: PM1 arn:aws:sqs:*:111111111111 does not match Q (inverted from match)',
    policyType: 'resource',
    notResourceStatements: ['arn:aws:sqs:*:111111111111'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [{ resource: 'arn:aws:sqs:*:111111111111', matches: false }]
  },
  {
    name: 'vpce NotResource: PM1 arn:aws:sqs:*:111111111111 does not match Q (inverted from match)',
    policyType: 'vpce',
    notResourceStatements: ['arn:aws:sqs:*:111111111111'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [{ resource: 'arn:aws:sqs:*:111111111111', matches: false }]
  },
  {
    name: 'scp NotResource: PM1 arn:aws:sqs:*:111111111111 rejected (wildcard in middle, not at end)',
    policyType: 'scp',
    effect: 'Deny',
    notResourceStatements: ['arn:aws:sqs:*:111111111111'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [
      {
        resource: 'arn:aws:sqs:*:111111111111',
        matches: false,
        errors: ['Policy resource ARN is not valid for this policy type']
      }
    ]
  },
  {
    name: 'rcp NotResource: PM1 arn:aws:sqs:*:111111111111 rejected (errors not inverted)',
    policyType: 'rcp',
    effect: 'Deny',
    notResourceStatements: ['arn:aws:sqs:*:111111111111'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [
      {
        resource: 'arn:aws:sqs:*:111111111111',
        matches: false,
        errors: ['Policy resource ARN is not valid for this policy type']
      }
    ]
  },

  // ── Middle-wildcard NotResource tests: PM2 arn:aws:sqs:*:111111111111:test-queue (6 seg) ──
  {
    name: 'identity NotResource: PM2 arn:aws:sqs:*:111111111111:test-queue does not match Q (inverted from match)',
    policyType: 'identity',
    notResourceStatements: ['arn:aws:sqs:*:111111111111:test-queue'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [{ resource: 'arn:aws:sqs:*:111111111111:test-queue', matches: false }]
  },
  {
    name: 'session NotResource: PM2 arn:aws:sqs:*:111111111111:test-queue does not match Q (inverted from match)',
    policyType: 'session',
    notResourceStatements: ['arn:aws:sqs:*:111111111111:test-queue'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [{ resource: 'arn:aws:sqs:*:111111111111:test-queue', matches: false }]
  },
  {
    name: 'pb NotResource: PM2 arn:aws:sqs:*:111111111111:test-queue does not match Q (inverted from match)',
    policyType: 'pb',
    notResourceStatements: ['arn:aws:sqs:*:111111111111:test-queue'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [{ resource: 'arn:aws:sqs:*:111111111111:test-queue', matches: false }]
  },
  {
    name: 'resource NotResource: PM2 arn:aws:sqs:*:111111111111:test-queue does not match Q (inverted from match)',
    policyType: 'resource',
    notResourceStatements: ['arn:aws:sqs:*:111111111111:test-queue'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [{ resource: 'arn:aws:sqs:*:111111111111:test-queue', matches: false }]
  },
  {
    name: 'vpce NotResource: PM2 arn:aws:sqs:*:111111111111:test-queue does not match Q (inverted from match)',
    policyType: 'vpce',
    notResourceStatements: ['arn:aws:sqs:*:111111111111:test-queue'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [{ resource: 'arn:aws:sqs:*:111111111111:test-queue', matches: false }]
  },
  {
    name: 'scp NotResource: PM2 arn:aws:sqs:*:111111111111:test-queue does not match Q (inverted from match)',
    policyType: 'scp',
    effect: 'Deny',
    notResourceStatements: ['arn:aws:sqs:*:111111111111:test-queue'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [{ resource: 'arn:aws:sqs:*:111111111111:test-queue', matches: false }]
  },
  {
    name: 'rcp NotResource: PM2 arn:aws:sqs:*:111111111111:test-queue does not match Q (inverted from match)',
    policyType: 'rcp',
    effect: 'Deny',
    notResourceStatements: ['arn:aws:sqs:*:111111111111:test-queue'],
    resource: {
      resource: 'arn:aws:sqs:us-east-1:111111111111:test-queue',
      accountId: '111111111111'
    },
    expectMatch: false,
    explains: [{ resource: 'arn:aws:sqs:*:111111111111:test-queue', matches: false }]
  }
]

describe('requestMatchesNotResources', () => {
  for (const rt of notResourceTests) {
    const testFn = rt.only ? it.only : it
    testFn(rt.name || `should match ${rt.resource}`, () => {
      //Given a policy
      const policy = loadPolicy({
        Statement: {
          Effect: rt.effect ?? 'Allow',
          NotResource: rt.notResourceStatements
        }
      })

      //And a request with a resource
      const request = new AwsRequestImpl(
        'principal',
        rt.resource,
        's3:GetBucket',
        new RequestContextImpl(rt.context || {}),
        rt.wildcardOnlyAction
      )

      //When the request is checked against the resource statement
      const response = requestMatchesNotResources(
        request,
        (policy.statements()[0] as NotResourceStatement).notResources(),
        rt.resourceStatements ? 'Resource' : 'NotResource',
        rt.effect ?? 'Allow',
        rt.policyType ?? 'identity'
      )

      //Then the request should match the resource statement
      expect(response.matches).toBe(rt.expectMatch)
      validateExplains(rt.explains, response.explains)
    })
  }
})
