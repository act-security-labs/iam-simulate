import type { ResourceType } from '@actsecurity/iam-data'
import { loadPolicy, type Statement } from '@actsecurity/iam-policy'
import { describe, expect, it } from 'vitest'
import type { PolicyWithName } from '../core_engine/CoreSimulatorEngine.js'
import {
  getMatchingResourceStringsForPolicies,
  getResourceStringsFromStatement,
  statementAllowsAction,
  statementResourceStringsForResourceTypeAndPattern
} from './policyResources.js'

const s3ObjectType: ResourceType = {
  arn: 'arn:${Partition}:s3:::${BucketName}/${ObjectName}',
  key: 'object',
  conditionKeys: []
}

function getStatement(statement: Record<string, unknown>): Statement {
  return loadPolicy({ Statement: statement }).statements()[0]
}

function getPolicyWithName(
  statements: Record<string, unknown> | Record<string, unknown>[],
  name: string
): PolicyWithName {
  return loadPolicy({ Statement: statements }, { name }) as PolicyWithName
}

type StatementAllowsActionTestCase = {
  name: string
  statement: Record<string, unknown>
  action: string
  expected: boolean
}

const statementAllowsActionTests: StatementAllowsActionTestCase[] = [
  {
    name: 'returns true when Allow Action matches exactly',
    statement: { Effect: 'Allow', Action: 's3:GetObject', Resource: '*' },
    action: 's3:GetObject',
    expected: true
  },
  {
    name: 'returns true when Allow Action wildcard matches',
    statement: { Effect: 'Allow', Action: 's3:Get*', Resource: '*' },
    action: 's3:GetObject',
    expected: true
  },
  {
    name: 'returns false when Allow Action does not match',
    statement: { Effect: 'Allow', Action: 's3:PutObject', Resource: '*' },
    action: 's3:GetObject',
    expected: false
  },
  {
    name: 'returns false when Effect is Deny even if Action matches',
    statement: { Effect: 'Deny', Action: 's3:GetObject', Resource: '*' },
    action: 's3:GetObject',
    expected: false
  },
  {
    name: 'returns false when Allow NotAction includes requested action',
    statement: { Effect: 'Allow', NotAction: 's3:GetObject', Resource: '*' },
    action: 's3:GetObject',
    expected: false
  },
  {
    name: 'returns true when Allow NotAction does not include requested action',
    statement: { Effect: 'Allow', NotAction: 's3:DeleteObject', Resource: '*' },
    action: 's3:GetObject',
    expected: true
  },
  {
    name: 'returns false for non-action statements',
    statement: { Effect: 'Allow', Principal: '*' },
    action: 's3:GetObject',
    expected: false
  }
]

type StatementResourceStringsTestCase = {
  name: string
  statement: Record<string, unknown>
  resourceType?: ResourceType
  resourceArnPattern: string
  expected: string[]
}

const statementResourceStringsTests: StatementResourceStringsTestCase[] = [
  {
    name: 'returns only Allow Resource strings that match type and overlap the request pattern',
    statement: {
      Effect: 'Allow',
      Action: 's3:GetObject',
      Resource: [
        'arn:aws:s3:::my-bucket/public/*',
        'arn:aws:s3:::my-bucket/private/*',
        'arn:aws:s3:::my-bucket',
        'arn:aws:ec2:us-east-1:123456789012:instance/*'
      ]
    },
    resourceArnPattern: 'arn:aws:s3:::my-bucket/public/reports/*',
    expected: ['arn:aws:s3:::my-bucket/public/*']
  },
  {
    name: 'returns an empty array when no Allow Resource strings overlap',
    statement: {
      Effect: 'Allow',
      Action: 's3:GetObject',
      Resource: ['arn:aws:s3:::other-bucket/*']
    },
    resourceArnPattern: 'arn:aws:s3:::my-bucket/*',
    expected: []
  },
  {
    name: 'returns empty when resource string partition does not match resource type partition',
    statement: {
      Effect: 'Allow',
      Action: 's3:GetObject',
      Resource: ['arn:aws:s3:::my-bucket/*']
    },
    resourceType: {
      arn: 'arn:aws-us-gov:s3:::${BucketName}/${ObjectName}',
      key: 'object',
      conditionKeys: []
    },
    resourceArnPattern: 'arn:aws:s3:::my-bucket/*',
    expected: []
  },
  {
    name: 'returns empty when resource string account does not match resource type account',
    statement: {
      Effect: 'Allow',
      Action: 'ec2:DescribeInstances',
      Resource: ['arn:aws:ec2:us-east-1:111111111111:instance/i-*']
    },
    resourceType: {
      arn: 'arn:${Partition}:ec2:${Region}:222222222222:instance/${InstanceId}',
      key: 'instance',
      conditionKeys: []
    },
    resourceArnPattern: 'arn:aws:ec2:us-east-1:111111111111:instance/i-*',
    expected: []
  },
  {
    name: 'matches when last non-variable resource component uses trailing wildcard',
    statement: {
      Effect: 'Allow',
      Action: 's3:GetObject',
      Resource: ['arn:aws:s3:::examplebucket/public*']
    },
    resourceType: {
      arn: 'arn:${Partition}:s3:::${BucketName}/public',
      key: 'bucket-public-prefix',
      conditionKeys: []
    },
    resourceArnPattern: 'arn:aws:s3:::examplebucket/public-readme',
    expected: ['arn:aws:s3:::examplebucket/public*']
  },
  {
    name: 'returns empty array for Allow NotResource when a not-resource equals the request pattern',
    statement: {
      Effect: 'Allow',
      Action: 's3:GetObject',
      NotResource: ['arn:aws:s3:::my-bucket/*']
    },
    resourceArnPattern: 'arn:aws:s3:::my-bucket/*',
    expected: []
  },
  {
    name: 'returns empty array for Allow NotResource when a not-resource is a superset of request pattern',
    statement: {
      Effect: 'Allow',
      Action: 's3:GetObject',
      NotResource: ['arn:aws:s3:::my-bucket/*']
    },
    resourceArnPattern: 'arn:aws:s3:::my-bucket/private/*',
    expected: []
  },
  {
    name: 'returns wildcard for Allow NotResource when no not-resource is a superset',
    statement: {
      Effect: 'Allow',
      Action: 's3:GetObject',
      NotResource: ['arn:aws:s3:::other-bucket/*']
    },
    resourceArnPattern: 'arn:aws:s3:::my-bucket/*',
    expected: ['*']
  },
  {
    name: 'returns the original pattern for statements without Resource/NotResource',
    statement: {
      Effect: 'Allow',
      Action: 'sts:AssumeRole',
      Principal: '*'
    },
    resourceArnPattern: 'arn:aws:s3:::my-bucket/*',
    expected: ['arn:aws:s3:::my-bucket/*']
  }
]

type GetResourceStringsFromStatementTestCase = {
  name: string
  statement: Record<string, unknown>
  action: string
  resourceArnPattern: string
  expected: string[]
}

const getResourceStringsFromStatementTests: GetResourceStringsFromStatementTestCase[] = [
  {
    name: 'returns matching resource strings when statement allows the action',
    statement: {
      Effect: 'Allow',
      Action: 's3:GetObject',
      Resource: ['arn:aws:s3:::my-bucket/*']
    },
    action: 's3:GetObject',
    resourceArnPattern: 'arn:aws:s3:::my-bucket/private/*',
    expected: ['arn:aws:s3:::my-bucket/*']
  },
  {
    name: 'returns empty array when action does not match',
    statement: {
      Effect: 'Allow',
      Action: 's3:PutObject',
      Resource: ['arn:aws:s3:::my-bucket/*']
    },
    action: 's3:GetObject',
    resourceArnPattern: 'arn:aws:s3:::my-bucket/private/*',
    expected: []
  },
  {
    name: 'returns wildcard for NotAction statements that still allow the action',
    statement: {
      Effect: 'Allow',
      NotAction: 's3:DeleteObject',
      NotResource: ['arn:aws:s3:::blocked-bucket/*']
    },
    action: 's3:GetObject',
    resourceArnPattern: 'arn:aws:s3:::my-bucket/private/*',
    expected: ['*']
  },
  {
    name: 'returns empty array for NotAction statements that explicitly exclude the action',
    statement: {
      Effect: 'Allow',
      NotAction: 's3:GetObject',
      Resource: ['arn:aws:s3:::my-bucket/*']
    },
    action: 's3:GetObject',
    resourceArnPattern: 'arn:aws:s3:::my-bucket/private/*',
    expected: []
  }
]

type GetMatchingResourceStringsForPoliciesTestCase = {
  name: string
  policies: (PolicyWithName | undefined)[]
  action: string
  resourceArnPattern: string
  expected: string[]
}

const getMatchingResourceStringsForPoliciesTests: GetMatchingResourceStringsForPoliciesTestCase[] =
  [
    {
      name: 'collects unique resource strings across policies and skips undefined policies',
      policies: [
        undefined,
        getPolicyWithName(
          [
            {
              Effect: 'Allow',
              Action: 's3:GetObject',
              Resource: ['arn:aws:s3:::bucket-a/*', 'arn:aws:s3:::bucket-shared/*']
            },
            {
              Effect: 'Allow',
              Action: 's3:PutObject',
              Resource: ['arn:aws:s3:::bucket-put/*']
            }
          ],
          'PolicyA'
        ),
        getPolicyWithName(
          [
            {
              Effect: 'Allow',
              Action: 's3:Get*',
              Resource: ['arn:aws:s3:::bucket-shared/*', 'arn:aws:s3:::bucket-b/*']
            },
            {
              Effect: 'Allow',
              Action: 's3:GetObject',
              NotResource: ['arn:aws:s3:::blocked-bucket/*']
            }
          ],
          'PolicyB'
        )
      ],
      action: 's3:GetObject',
      resourceArnPattern: 'arn:aws:s3:::bucket-*/*',
      expected: [
        'arn:aws:s3:::bucket-a/*',
        'arn:aws:s3:::bucket-shared/*',
        'arn:aws:s3:::bucket-b/*',
        '*'
      ]
    },
    {
      name: 'returns an empty array when no statements allow the requested action',
      policies: [
        getPolicyWithName(
          [
            {
              Effect: 'Allow',
              Action: 's3:PutObject',
              Resource: ['arn:aws:s3:::bucket-a/*']
            },
            {
              Effect: 'Deny',
              Action: 's3:GetObject',
              Resource: ['arn:aws:s3:::bucket-a/*']
            }
          ],
          'NoMatches'
        )
      ],
      action: 's3:GetObject',
      resourceArnPattern: 'arn:aws:s3:::bucket-a/*',
      expected: []
    }
  ]

describe('statementAllowsAction', () => {
  for (const testCase of statementAllowsActionTests) {
    it(testCase.name, () => {
      const statement = getStatement(testCase.statement)
      const result = statementAllowsAction(statement, testCase.action)
      expect(result).toBe(testCase.expected)
    })
  }
})

describe('statementResourceStringsForResourceTypeAndPattern', () => {
  for (const testCase of statementResourceStringsTests) {
    it(testCase.name, () => {
      const statement = getStatement(testCase.statement)
      const result = statementResourceStringsForResourceTypeAndPattern(
        statement,
        testCase.resourceType ?? s3ObjectType,
        testCase.resourceArnPattern,
        true
      )
      expect(result).toEqual(testCase.expected)
    })
  }
})

describe('getResourceStringsFromStatement', () => {
  for (const testCase of getResourceStringsFromStatementTests) {
    it(testCase.name, () => {
      const statement = getStatement(testCase.statement)
      const result = getResourceStringsFromStatement(
        statement,
        testCase.action,
        s3ObjectType,
        testCase.resourceArnPattern,
        true
      )
      expect(result).toEqual(testCase.expected)
    })
  }
})

describe('getMatchingResourceStringsForPolicies', () => {
  for (const testCase of getMatchingResourceStringsForPoliciesTests) {
    it(testCase.name, () => {
      const result = getMatchingResourceStringsForPolicies(
        testCase.policies,
        testCase.action,
        s3ObjectType,
        testCase.resourceArnPattern
      )
      expect(result).toEqual(testCase.expected)
    })
  }
})
