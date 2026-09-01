import { loadPolicy } from '@actsecurity/iam-policy'
import { describe, expect, it } from 'vitest'
import { and, denyStatementEscapeExpression, invertCondition, or } from './allowedConditions.js'
import type { AllowedConditionExpression, AllowedConditionSource } from '../evaluate.js'
import type { StatementAnalysis } from '../StatementAnalysis.js'

const source: AllowedConditionSource = {
  policyType: 'identity',
  effect: 'Deny',
  policyIdentifier: 'test-policy',
  statementIndex: 1
}

const sourceVpcCondition: AllowedConditionExpression = {
  conditionType: 'condition',
  op: 'StringEquals',
  key: 'aws:SourceVpc',
  values: ['vpc-123'],
  sources: [source]
}

const sourceIpCondition: AllowedConditionExpression = {
  conditionType: 'condition',
  op: 'IpAddress',
  key: 'aws:SourceIp',
  values: ['203.0.113.0/24'],
  sources: [source]
}

const sourceVpceCondition: AllowedConditionExpression = {
  conditionType: 'condition',
  op: 'StringEquals',
  key: 'aws:SourceVpce',
  values: ['vpce-123'],
  sources: [source]
}

function conditionFor(operator: string, key: string, values: string | string[]) {
  const policy = loadPolicy(
    {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Deny',
          Action: '*',
          Resource: '*',
          Condition: { [operator]: { [key]: values } }
        }
      ]
    },
    { name: 'test-policy' }
  )
  return policy.statements()[0].conditions()[0]
}

function statementWithIgnoredConditions(
  conditions: ReturnType<typeof conditionFor>[]
): StatementAnalysis {
  const statement = loadPolicy(
    {
      Version: '2012-10-17',
      Statement: [{ Effect: 'Deny', Action: '*', Resource: '*' }]
    },
    { name: 'test-policy' }
  ).statements()[0]

  return {
    policyId: 'test-policy',
    statement,
    resourceMatch: true,
    actionMatch: true,
    principalMatch: 'Match',
    conditionMatch: 'NoMatch',
    ignoredConditions: conditions,
    explain: {
      effect: 'Deny',
      identifier: '1',
      matches: false,
      actionMatch: true,
      principalMatch: 'Match',
      resourceMatch: true,
      conditionMatch: false
    }
  }
}

function invertedCondition(op: string, key: string, values: string[]): AllowedConditionExpression {
  return {
    conditionType: 'condition',
    op,
    key,
    values,
    sources: [source],
    inverted: true
  }
}

const expressionHelperTests: {
  name: string
  expression: () => AllowedConditionExpression
  expected: AllowedConditionExpression
}[] = [
  {
    name: 'simplifies OR with an unconditional branch to always',
    expression: () => or([sourceVpcCondition, { conditionType: 'always' }]),
    expected: { conditionType: 'always' }
  },
  {
    name: 'simplifies AND with a never branch to never',
    expression: () =>
      and([
        sourceVpcCondition,
        { conditionType: 'never', reason: 'explicitDenyWithoutConditions' }
      ]),
    expected: { conditionType: 'never', reason: 'explicitDenyWithoutConditions' }
  },
  {
    name: 'flattens nested AND groups',
    expression: () => and([and([sourceVpcCondition, sourceIpCondition]), sourceVpceCondition]),
    expected: {
      conditionType: 'group',
      operator: 'and',
      conditions: [sourceVpcCondition, sourceIpCondition, sourceVpceCondition]
    }
  },
  {
    name: 'flattens nested OR groups',
    expression: () => or([or([sourceVpcCondition, sourceIpCondition]), sourceVpceCondition]),
    expected: {
      conditionType: 'group',
      operator: 'or',
      conditions: [sourceVpcCondition, sourceIpCondition, sourceVpceCondition]
    }
  }
]

describe('allowed condition expression helpers', () => {
  for (const testCase of expressionHelperTests) {
    it(testCase.name, () => {
      //Given expression inputs defined by the test case
      //When the expression is built and simplified
      const result = testCase.expression()

      //Then the result should match the expected simplified expression
      expect(result).toEqual(testCase.expected)
    })
  }
})

const invertConditionTests: {
  name: string
  op: string
  key: string
  values: string[]
  expected: AllowedConditionExpression
}[] = [
  {
    name: 'inverts StringEquals to StringNotEquals with the same values',
    op: 'StringEquals',
    key: 'aws:ExampleKey',
    values: ['expected'],
    expected: invertedCondition('StringNotEquals', 'aws:ExampleKey', ['expected'])
  },
  {
    name: 'inverts StringNotEquals to StringEquals with the same values',
    op: 'StringNotEquals',
    key: 'aws:ExampleKey',
    values: ['expected'],
    expected: invertedCondition('StringEquals', 'aws:ExampleKey', ['expected'])
  },
  {
    name: 'inverts StringEqualsIgnoreCase to StringNotEqualsIgnoreCase with the same values',
    op: 'StringEqualsIgnoreCase',
    key: 'aws:ExampleKey',
    values: ['Expected'],
    expected: invertedCondition('StringNotEqualsIgnoreCase', 'aws:ExampleKey', ['Expected'])
  },
  {
    name: 'inverts StringNotEqualsIgnoreCase to StringEqualsIgnoreCase with the same values',
    op: 'StringNotEqualsIgnoreCase',
    key: 'aws:ExampleKey',
    values: ['Expected'],
    expected: invertedCondition('StringEqualsIgnoreCase', 'aws:ExampleKey', ['Expected'])
  },
  {
    name: 'inverts StringLike to StringNotLike with the same values',
    op: 'StringLike',
    key: 'aws:ExampleKey',
    values: ['prod-*'],
    expected: invertedCondition('StringNotLike', 'aws:ExampleKey', ['prod-*'])
  },
  {
    name: 'inverts StringNotLike to StringLike with the same values',
    op: 'StringNotLike',
    key: 'aws:ExampleKey',
    values: ['prod-*'],
    expected: invertedCondition('StringLike', 'aws:ExampleKey', ['prod-*'])
  },
  {
    name: 'inverts ArnEquals to ArnNotEquals with the same values',
    op: 'ArnEquals',
    key: 'aws:PrincipalArn',
    values: ['arn:aws:iam::123456789012:role/Admin'],
    expected: invertedCondition('ArnNotEquals', 'aws:PrincipalArn', [
      'arn:aws:iam::123456789012:role/Admin'
    ])
  },
  {
    name: 'inverts ArnNotEquals to ArnEquals with the same values',
    op: 'ArnNotEquals',
    key: 'aws:PrincipalArn',
    values: ['arn:aws:iam::123456789012:role/Admin'],
    expected: invertedCondition('ArnEquals', 'aws:PrincipalArn', [
      'arn:aws:iam::123456789012:role/Admin'
    ])
  },
  {
    name: 'inverts ArnLike to ArnNotLike with the same values',
    op: 'ArnLike',
    key: 'aws:PrincipalArn',
    values: ['arn:aws:iam::*:role/Admin*'],
    expected: invertedCondition('ArnNotLike', 'aws:PrincipalArn', ['arn:aws:iam::*:role/Admin*'])
  },
  {
    name: 'inverts ArnNotLike to ArnLike with the same values',
    op: 'ArnNotLike',
    key: 'aws:PrincipalArn',
    values: ['arn:aws:iam::*:role/Admin*'],
    expected: invertedCondition('ArnLike', 'aws:PrincipalArn', ['arn:aws:iam::*:role/Admin*'])
  },
  {
    name: 'inverts NumericEquals to NumericNotEquals with the same values',
    op: 'NumericEquals',
    key: 's3:TlsVersion',
    values: ['1.2'],
    expected: invertedCondition('NumericNotEquals', 's3:TlsVersion', ['1.2'])
  },
  {
    name: 'inverts NumericNotEquals to NumericEquals with the same values',
    op: 'NumericNotEquals',
    key: 's3:TlsVersion',
    values: ['1.2'],
    expected: invertedCondition('NumericEquals', 's3:TlsVersion', ['1.2'])
  },
  {
    name: 'inverts NumericLessThan to NumericGreaterThanEquals with the same values',
    op: 'NumericLessThan',
    key: 's3:TlsVersion',
    values: ['1.2'],
    expected: invertedCondition('NumericGreaterThanEquals', 's3:TlsVersion', ['1.2'])
  },
  {
    name: 'inverts NumericLessThanEquals to NumericGreaterThan with the same values',
    op: 'NumericLessThanEquals',
    key: 's3:TlsVersion',
    values: ['1.2'],
    expected: invertedCondition('NumericGreaterThan', 's3:TlsVersion', ['1.2'])
  },
  {
    name: 'inverts NumericGreaterThan to NumericLessThanEquals with the same values',
    op: 'NumericGreaterThan',
    key: 's3:TlsVersion',
    values: ['1.2'],
    expected: invertedCondition('NumericLessThanEquals', 's3:TlsVersion', ['1.2'])
  },
  {
    name: 'inverts NumericGreaterThanEquals to NumericLessThan with the same values',
    op: 'NumericGreaterThanEquals',
    key: 's3:TlsVersion',
    values: ['1.2'],
    expected: invertedCondition('NumericLessThan', 's3:TlsVersion', ['1.2'])
  },
  {
    name: 'inverts DateEquals to DateNotEquals with the same values',
    op: 'DateEquals',
    key: 'aws:CurrentTime',
    values: ['2024-01-01T00:00:00Z'],
    expected: invertedCondition('DateNotEquals', 'aws:CurrentTime', ['2024-01-01T00:00:00Z'])
  },
  {
    name: 'inverts DateNotEquals to DateEquals with the same values',
    op: 'DateNotEquals',
    key: 'aws:CurrentTime',
    values: ['2024-01-01T00:00:00Z'],
    expected: invertedCondition('DateEquals', 'aws:CurrentTime', ['2024-01-01T00:00:00Z'])
  },
  {
    name: 'inverts DateLessThan to DateGreaterThanEquals with the same values',
    op: 'DateLessThan',
    key: 'aws:CurrentTime',
    values: ['2024-01-01T00:00:00Z'],
    expected: invertedCondition('DateGreaterThanEquals', 'aws:CurrentTime', [
      '2024-01-01T00:00:00Z'
    ])
  },
  {
    name: 'inverts DateLessThanEquals to DateGreaterThan with the same values',
    op: 'DateLessThanEquals',
    key: 'aws:CurrentTime',
    values: ['2024-01-01T00:00:00Z'],
    expected: invertedCondition('DateGreaterThan', 'aws:CurrentTime', ['2024-01-01T00:00:00Z'])
  },
  {
    name: 'inverts DateGreaterThan to DateLessThanEquals with the same values',
    op: 'DateGreaterThan',
    key: 'aws:CurrentTime',
    values: ['2024-01-01T00:00:00Z'],
    expected: invertedCondition('DateLessThanEquals', 'aws:CurrentTime', ['2024-01-01T00:00:00Z'])
  },
  {
    name: 'inverts DateGreaterThanEquals to DateLessThan with the same values',
    op: 'DateGreaterThanEquals',
    key: 'aws:CurrentTime',
    values: ['2024-01-01T00:00:00Z'],
    expected: invertedCondition('DateLessThan', 'aws:CurrentTime', ['2024-01-01T00:00:00Z'])
  },
  {
    name: 'inverts IpAddress to NotIpAddress with the same values',
    op: 'IpAddress',
    key: 'aws:SourceIp',
    values: ['192.0.2.0/24'],
    expected: invertedCondition('NotIpAddress', 'aws:SourceIp', ['192.0.2.0/24'])
  },
  {
    name: 'inverts NotIpAddress to IpAddress with the same values',
    op: 'NotIpAddress',
    key: 'aws:SourceIp',
    values: ['192.0.2.0/24'],
    expected: invertedCondition('IpAddress', 'aws:SourceIp', ['192.0.2.0/24'])
  },
  {
    name: 'inverts BinaryEquals to synthetic BinaryNotEquals with the same values',
    op: 'BinaryEquals',
    key: 'aws:BinaryKey',
    values: ['AAAA'],
    expected: invertedCondition('BinaryNotEquals', 'aws:BinaryKey', ['AAAA'])
  },
  {
    name: 'inverts synthetic BinaryNotEquals to BinaryEquals with the same values',
    op: 'BinaryNotEquals',
    key: 'aws:BinaryKey',
    values: ['AAAA'],
    expected: invertedCondition('BinaryEquals', 'aws:BinaryKey', ['AAAA'])
  },
  {
    name: 'inverts Bool true to Bool false',
    op: 'Bool',
    key: 'aws:SecureTransport',
    values: ['true'],
    expected: invertedCondition('Bool', 'aws:SecureTransport', ['false'])
  },
  {
    name: 'inverts Null true to Null false',
    op: 'Null',
    key: 'aws:SourceVpc',
    values: ['true'],
    expected: invertedCondition('Null', 'aws:SourceVpc', ['false'])
  },
  {
    name: 'inverts StringEqualsIfExists to present key and StringNotEquals with the same values',
    op: 'StringEqualsIfExists',
    key: 'aws:SourceVpc',
    values: ['vpc-123'],
    expected: {
      conditionType: 'group',
      operator: 'and',
      conditions: [
        invertedCondition('Null', 'aws:SourceVpc', ['false']),
        invertedCondition('StringNotEquals', 'aws:SourceVpc', ['vpc-123'])
      ]
    }
  },
  {
    name: 'inverts StringNotEqualsIfExists to StringEquals with the same value because the null check is redundant',
    op: 'StringNotEqualsIfExists',
    key: 'aws:SourceVpc',
    values: ['vpc-123'],
    expected: invertedCondition('StringEquals', 'aws:SourceVpc', ['vpc-123'])
  },
  {
    name: 'inverts StringNotEqualsIfExists to StringEquals with multiple values because the null check is redundant',
    op: 'StringNotEqualsIfExists',
    key: 'aws:SourceVpc',
    values: ['vpc-123', 'vpc-456'],
    expected: invertedCondition('StringEquals', 'aws:SourceVpc', ['vpc-123', 'vpc-456'])
  },
  {
    name: 'inverts ForAllValues:StringEquals to present key and ForAnyValue:StringNotEquals',
    op: 'ForAllValues:StringEquals',
    key: 'aws:SourceOrgPaths',
    values: ['o-1/*'],
    expected: {
      conditionType: 'group',
      operator: 'and',
      conditions: [
        invertedCondition('Null', 'aws:SourceOrgPaths', ['false']),
        invertedCondition('ForAnyValue:StringNotEquals', 'aws:SourceOrgPaths', ['o-1/*'])
      ]
    }
  },
  {
    name: 'inverts ForAnyValue:StringEquals to missing key or ForAllValues:StringNotEquals',
    op: 'ForAnyValue:StringEquals',
    key: 'aws:SourceOrgPaths',
    values: ['o-1/*'],
    expected: {
      conditionType: 'group',
      operator: 'or',
      conditions: [
        invertedCondition('Null', 'aws:SourceOrgPaths', ['true']),
        invertedCondition('ForAllValues:StringNotEquals', 'aws:SourceOrgPaths', ['o-1/*'])
      ]
    }
  },
  {
    name: 'inverts ForAllValues:StringNotEquals to present key and ForAnyValue:StringEquals',
    op: 'ForAllValues:StringNotEquals',
    key: 'aws:SourceOrgPaths',
    values: ['o-1/*'],
    expected: {
      conditionType: 'group',
      operator: 'and',
      conditions: [
        invertedCondition('Null', 'aws:SourceOrgPaths', ['false']),
        invertedCondition('ForAnyValue:StringEquals', 'aws:SourceOrgPaths', ['o-1/*'])
      ]
    }
  },
  {
    name: 'inverts ForAnyValue:StringNotEquals to missing key or ForAllValues:StringEquals',
    op: 'ForAnyValue:StringNotEquals',
    key: 'aws:SourceOrgPaths',
    values: ['o-1/*'],
    expected: {
      conditionType: 'group',
      operator: 'or',
      conditions: [
        invertedCondition('Null', 'aws:SourceOrgPaths', ['true']),
        invertedCondition('ForAllValues:StringEquals', 'aws:SourceOrgPaths', ['o-1/*'])
      ]
    }
  },
  {
    name: 'inverts ForAllValues:ArnLike to present key and ForAnyValue:ArnNotLike',
    op: 'ForAllValues:ArnLike',
    key: 'aws:PrincipalArn',
    values: ['arn:aws:iam::*:role/Admin*'],
    expected: {
      conditionType: 'group',
      operator: 'and',
      conditions: [
        invertedCondition('Null', 'aws:PrincipalArn', ['false']),
        invertedCondition('ForAnyValue:ArnNotLike', 'aws:PrincipalArn', [
          'arn:aws:iam::*:role/Admin*'
        ])
      ]
    }
  },
  {
    name: 'inverts ForAnyValue:ArnLike to missing key or ForAllValues:ArnNotLike',
    op: 'ForAnyValue:ArnLike',
    key: 'aws:PrincipalArn',
    values: ['arn:aws:iam::*:role/Admin*'],
    expected: {
      conditionType: 'group',
      operator: 'or',
      conditions: [
        invertedCondition('Null', 'aws:PrincipalArn', ['true']),
        invertedCondition('ForAllValues:ArnNotLike', 'aws:PrincipalArn', [
          'arn:aws:iam::*:role/Admin*'
        ])
      ]
    }
  },
  {
    name: 'preserves multiple values when inverting ForAllValues:StringEquals',
    op: 'ForAllValues:StringEquals',
    key: 'aws:SourceOrgPaths',
    values: ['o-1/*', 'o-2/*'],
    expected: {
      conditionType: 'group',
      operator: 'and',
      conditions: [
        invertedCondition('Null', 'aws:SourceOrgPaths', ['false']),
        invertedCondition('ForAnyValue:StringNotEquals', 'aws:SourceOrgPaths', ['o-1/*', 'o-2/*'])
      ]
    }
  },
  {
    name: 'inverts ForAllValues:StringEqualsIfExists without duplicating present-key requirement',
    op: 'ForAllValues:StringEqualsIfExists',
    key: 'aws:SourceOrgPaths',
    values: ['o-1/*'],
    expected: {
      conditionType: 'group',
      operator: 'and',
      conditions: [
        invertedCondition('Null', 'aws:SourceOrgPaths', ['false']),
        invertedCondition('ForAnyValue:StringNotEquals', 'aws:SourceOrgPaths', ['o-1/*'])
      ]
    }
  },
  {
    name: 'inverts ForAnyValue:StringEqualsIfExists with present-key requirement around the ForAnyValue inverse',
    op: 'ForAnyValue:StringEqualsIfExists',
    key: 'aws:SourceOrgPaths',
    values: ['o-1/*'],
    expected: {
      conditionType: 'group',
      operator: 'and',
      conditions: [
        invertedCondition('Null', 'aws:SourceOrgPaths', ['false']),
        {
          conditionType: 'group',
          operator: 'or',
          conditions: [
            invertedCondition('Null', 'aws:SourceOrgPaths', ['true']),
            invertedCondition('ForAllValues:StringNotEquals', 'aws:SourceOrgPaths', ['o-1/*'])
          ]
        }
      ]
    }
  },
  {
    name: 'inverts ForAllValues:StringNotEqualsIfExists without adding a redundant present-key requirement',
    op: 'ForAllValues:StringNotEqualsIfExists',
    key: 'aws:SourceOrgPaths',
    values: ['o-1/*'],
    expected: {
      conditionType: 'group',
      operator: 'and',
      conditions: [
        invertedCondition('Null', 'aws:SourceOrgPaths', ['false']),
        invertedCondition('ForAnyValue:StringEquals', 'aws:SourceOrgPaths', ['o-1/*'])
      ]
    }
  },
  {
    name: 'inverts ForAnyValue:StringNotEqualsIfExists without adding a redundant present-key requirement',
    op: 'ForAnyValue:StringNotEqualsIfExists',
    key: 'aws:SourceOrgPaths',
    values: ['o-1/*'],
    expected: {
      conditionType: 'group',
      operator: 'or',
      conditions: [
        invertedCondition('Null', 'aws:SourceOrgPaths', ['true']),
        invertedCondition('ForAllValues:StringEquals', 'aws:SourceOrgPaths', ['o-1/*'])
      ]
    }
  }
]

const singleValueIfExistsInversionTests: {
  op: string
  key: string
  values: string[]
  expectedOp: string
  expectedValues?: string[]
}[] = [
  {
    op: 'StringEquals',
    key: 'aws:ExampleKey',
    values: ['expected'],
    expectedOp: 'StringNotEquals'
  },
  {
    op: 'StringNotEquals',
    key: 'aws:ExampleKey',
    values: ['expected'],
    expectedOp: 'StringEquals'
  },
  {
    op: 'StringEqualsIgnoreCase',
    key: 'aws:ExampleKey',
    values: ['Expected'],
    expectedOp: 'StringNotEqualsIgnoreCase'
  },
  {
    op: 'StringNotEqualsIgnoreCase',
    key: 'aws:ExampleKey',
    values: ['Expected'],
    expectedOp: 'StringEqualsIgnoreCase'
  },
  { op: 'StringLike', key: 'aws:ExampleKey', values: ['prod-*'], expectedOp: 'StringNotLike' },
  { op: 'StringNotLike', key: 'aws:ExampleKey', values: ['prod-*'], expectedOp: 'StringLike' },
  {
    op: 'ArnEquals',
    key: 'aws:PrincipalArn',
    values: ['arn:aws:iam::123456789012:role/Admin'],
    expectedOp: 'ArnNotEquals'
  },
  {
    op: 'ArnNotEquals',
    key: 'aws:PrincipalArn',
    values: ['arn:aws:iam::123456789012:role/Admin'],
    expectedOp: 'ArnEquals'
  },
  {
    op: 'ArnLike',
    key: 'aws:PrincipalArn',
    values: ['arn:aws:iam::*:role/Admin*'],
    expectedOp: 'ArnNotLike'
  },
  {
    op: 'ArnNotLike',
    key: 'aws:PrincipalArn',
    values: ['arn:aws:iam::*:role/Admin*'],
    expectedOp: 'ArnLike'
  },
  { op: 'NumericEquals', key: 's3:TlsVersion', values: ['1.2'], expectedOp: 'NumericNotEquals' },
  { op: 'NumericNotEquals', key: 's3:TlsVersion', values: ['1.2'], expectedOp: 'NumericEquals' },
  {
    op: 'NumericLessThan',
    key: 's3:TlsVersion',
    values: ['1.2'],
    expectedOp: 'NumericGreaterThanEquals'
  },
  {
    op: 'NumericLessThanEquals',
    key: 's3:TlsVersion',
    values: ['1.2'],
    expectedOp: 'NumericGreaterThan'
  },
  {
    op: 'NumericGreaterThan',
    key: 's3:TlsVersion',
    values: ['1.2'],
    expectedOp: 'NumericLessThanEquals'
  },
  {
    op: 'NumericGreaterThanEquals',
    key: 's3:TlsVersion',
    values: ['1.2'],
    expectedOp: 'NumericLessThan'
  },
  {
    op: 'DateEquals',
    key: 'aws:CurrentTime',
    values: ['2024-01-01T00:00:00Z'],
    expectedOp: 'DateNotEquals'
  },
  {
    op: 'DateNotEquals',
    key: 'aws:CurrentTime',
    values: ['2024-01-01T00:00:00Z'],
    expectedOp: 'DateEquals'
  },
  {
    op: 'DateLessThan',
    key: 'aws:CurrentTime',
    values: ['2024-01-01T00:00:00Z'],
    expectedOp: 'DateGreaterThanEquals'
  },
  {
    op: 'DateLessThanEquals',
    key: 'aws:CurrentTime',
    values: ['2024-01-01T00:00:00Z'],
    expectedOp: 'DateGreaterThan'
  },
  {
    op: 'DateGreaterThan',
    key: 'aws:CurrentTime',
    values: ['2024-01-01T00:00:00Z'],
    expectedOp: 'DateLessThanEquals'
  },
  {
    op: 'DateGreaterThanEquals',
    key: 'aws:CurrentTime',
    values: ['2024-01-01T00:00:00Z'],
    expectedOp: 'DateLessThan'
  },
  { op: 'IpAddress', key: 'aws:SourceIp', values: ['192.0.2.0/24'], expectedOp: 'NotIpAddress' },
  { op: 'NotIpAddress', key: 'aws:SourceIp', values: ['192.0.2.0/24'], expectedOp: 'IpAddress' },
  { op: 'BinaryEquals', key: 'aws:BinaryKey', values: ['AAAA'], expectedOp: 'BinaryNotEquals' },
  { op: 'BinaryNotEquals', key: 'aws:BinaryKey', values: ['AAAA'], expectedOp: 'BinaryEquals' },
  {
    op: 'Bool',
    key: 'aws:SecureTransport',
    values: ['true'],
    expectedOp: 'Bool',
    expectedValues: ['false']
  }
]

function negativeConditionOperatorMatchesMissingKeys(op: string): boolean {
  return new Set([
    'StringNotEquals',
    'StringNotEqualsIgnoreCase',
    'StringNotLike',
    'ArnNotEquals',
    'ArnNotLike',
    'NumericNotEquals',
    'DateNotEquals',
    'NotIpAddress',
    'BinaryNotEquals'
  ]).has(op)
}

invertConditionTests.push(
  ...singleValueIfExistsInversionTests.map((testCase) => {
    const invertedBase = invertedCondition(
      testCase.expectedOp,
      testCase.key,
      testCase.expectedValues ?? testCase.values
    )
    return {
      name: negativeConditionOperatorMatchesMissingKeys(testCase.op)
        ? `inverts ${testCase.op}IfExists to ${testCase.expectedOp} without a redundant null check`
        : `inverts ${testCase.op}IfExists to present key and ${testCase.expectedOp} with expected values`,
      op: `${testCase.op}IfExists`,
      key: testCase.key,
      values: testCase.values,
      expected: negativeConditionOperatorMatchesMissingKeys(testCase.op)
        ? invertedBase
        : {
            conditionType: 'group' as const,
            operator: 'and' as const,
            conditions: [invertedCondition('Null', testCase.key, ['false']), invertedBase]
          }
    }
  })
)

describe('invertCondition', () => {
  for (const testCase of invertConditionTests) {
    it(testCase.name, () => {
      //Given a condition using the operator and values from the test case
      const condition = conditionFor(testCase.op, testCase.key, testCase.values)

      //When the condition is inverted
      const result = invertCondition(condition, source)

      //Then the result should include the expected inverted operators and values
      expect(result).toEqual(testCase.expected)
    })
  }
})

const denyStatementEscapeTests: {
  name: string
  conditions: ReturnType<typeof conditionFor>[]
  expected: AllowedConditionExpression
}[] = [
  {
    name: 'inverts multiple deny conditions as an OR expression showing both inverted operators and values',
    conditions: [
      conditionFor('StringEquals', 'aws:SourceVpc', 'vpc-123'),
      conditionFor('IpAddress', 'aws:SourceIp', '192.0.2.0/24')
    ],
    expected: {
      conditionType: 'group',
      operator: 'or',
      conditions: [
        invertedCondition('StringNotEquals', 'aws:SourceVpc', ['vpc-123']),
        invertedCondition('NotIpAddress', 'aws:SourceIp', ['192.0.2.0/24'])
      ]
    }
  },
  {
    name: 'represents a conditionless deny as never allowed',
    conditions: [],
    expected: { conditionType: 'never', reason: 'explicitDenyWithoutConditions' }
  }
]

describe('denyStatementEscapeExpression', () => {
  for (const testCase of denyStatementEscapeTests) {
    it(testCase.name, () => {
      //Given a deny statement with ignored conditions from the test case
      const statement = statementWithIgnoredConditions(testCase.conditions)

      //When the deny statement is converted to an escape expression
      const result = denyStatementEscapeExpression(statement, 'identity')

      //Then the result should match the expected inverted expression
      expect(result).toEqual(testCase.expected)
    })
  }
})
