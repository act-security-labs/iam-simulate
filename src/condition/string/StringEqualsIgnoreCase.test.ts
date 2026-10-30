import { type BaseOperatorTest, testOperator } from '../baseConditionperatorTests.js'
import { StringEqualsIgnoreCase } from './StringEqualsIgnoreCase.js'

const stringEqualsIgnoreCaseTests: BaseOperatorTest[] = [
  {
    name: 'matches expanded lowercase mapping',
    requestContext: {},
    policyValues: ['İ'],
    testValue: 'i\u0307',
    expected: true,
    explains: [{ value: 'İ', matches: true }]
  },
  {
    name: 'compares regex metacharacters in variables literally',
    requestContext: { 'aws:username': 'a.b' },
    policyValues: ['${aws:username}'],
    testValue: 'aXb',
    expected: false,
    explains: [{ value: '${aws:username}', matches: false, resolvedValue: 'a.b' }]
  },
  {
    name: 'matches IAM escaped literal star',
    requestContext: {},
    policyValues: ['a${*}'],
    testValue: 'A*',
    expected: true,
    explains: [{ value: 'a${*}', matches: true }]
  },
  {
    name: 'does not match sigma and final sigma',
    requestContext: {},
    policyValues: ['σ'],
    testValue: 'ς',
    expected: false,
    explains: [{ value: 'σ', matches: false }]
  },
  {
    name: 'does not match i and dotted capital I',
    requestContext: {},
    policyValues: ['i'],
    testValue: 'İ',
    expected: false,
    explains: [{ value: 'i', matches: false }]
  },
  {
    name: 'does not match I and dotless i',
    requestContext: {},
    policyValues: ['I'],
    testValue: 'ı',
    expected: false,
    explains: [{ value: 'I', matches: false }]
  },
  {
    name: 'does not match s and long s',
    requestContext: {},
    policyValues: ['s'],
    testValue: 'ſ',
    expected: false,
    explains: [{ value: 's', matches: false }]
  },
  {
    name: 'does not match Deseret uppercase and lowercase',
    requestContext: {},
    policyValues: ['𐐀'],
    testValue: '𐐨',
    expected: false,
    explains: [{ value: '𐐀', matches: false }]
  },
  {
    name: 'matches Kelvin sign against ASCII K as AWS does',
    requestContext: {},
    policyValues: ['K'],
    testValue: 'K',
    expected: true,
    explains: [{ value: 'K', matches: true }]
  },
  {
    name: 'matches capital sharp s after resolving a policy variable',
    requestContext: { 'aws:username': 'ß' },
    policyValues: ['${aws:username}'],
    testValue: 'ẞ',
    expected: true,
    explains: [{ value: '${aws:username}', matches: true, resolvedValue: 'ß' }]
  },
  {
    name: 'does not match a trailing newline',
    requestContext: {},
    policyValues: ['abc'],
    testValue: 'abc\n',
    expected: false,
    explains: [{ value: 'abc', matches: false }]
  },
  {
    name: 'should return true if the strings are equal',
    requestContext: {},
    policyValues: ['test'],
    testValue: 'test',
    expected: true,
    explains: [
      {
        value: 'test',
        matches: true
      }
    ]
  },
  {
    name: 'should return true if the strings are equal but different case',
    requestContext: {},
    policyValues: ['test'],
    testValue: 'TEST',
    expected: true,
    explains: [
      {
        matches: true,
        value: 'test'
      }
    ]
  },
  {
    name: 'should return false if the strings are not equal',
    requestContext: {},
    policyValues: ['test'],
    testValue: 'test2',
    expected: false,
    explains: [
      {
        matches: false,
        value: 'test'
      }
    ]
  },
  {
    name: 'should replace variables in the policy value',
    requestContext: { 'aws:username': 'Bob' },
    policyValues: ['arn:aws:iam::123456789012:user/${aws:username}'],
    testValue: 'arn:aws:iam::123456789012:user/Bob',
    expected: true,
    explains: [
      {
        value: 'arn:aws:iam::123456789012:user/${aws:username}',
        matches: true,
        resolvedValue: 'arn:aws:iam::123456789012:user/Bob'
      }
    ]
  },
  {
    name: 'should ignore case in replaced variables',
    requestContext: { 'aws:username': 'BOB' },
    policyValues: ['arn:aws:iam::123456789012:user/${aws:username}'],
    testValue: 'arn:aws:iam::123456789012:user/bob',
    expected: true,
    explains: [
      {
        value: 'arn:aws:iam::123456789012:user/${aws:username}',
        matches: true,
        resolvedValue: 'arn:aws:iam::123456789012:user/BOB'
      }
    ]
  },
  {
    name: 'should ignore wildcards in the policy value',
    requestContext: {},
    policyValues: ['test*'],
    testValue: 'test123',
    expected: false,
    explains: [
      {
        value: 'test*',
        matches: false
      }
    ]
  },
  {
    name: 'should return replacement errors',
    requestContext: { 'aws:PrincipalOrgPaths': ['123', '456'] },
    policyValues: ['test${aws:PrincipalOrgPaths}'],
    testValue: 'test123',
    expected: false,
    explains: [
      {
        value: 'test${aws:PrincipalOrgPaths}',
        matches: false,
        errors: [
          '{aws:PrincipalOrgPaths} is a multi value context key, and cannot be used for replacement. This will never match'
        ]
      }
    ]
  }
]

testOperator('StringEqualsIgnoreCase', stringEqualsIgnoreCaseTests, StringEqualsIgnoreCase)
