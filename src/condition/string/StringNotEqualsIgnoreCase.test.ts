import { type BaseOperatorTest, testOperator } from '../baseConditionperatorTests.js'
import { StringNotEqualsIgnoreCase } from './StringNotEqualsIgnoreCase.js'

const stringNotEqualsIgnoreCaseTests: BaseOperatorTest[] = [
  {
    name: 'does not match expanded lowercase mapping',
    requestContext: {},
    policyValues: ['İ'],
    testValue: 'i\u0307',
    expected: false,
    explains: [{ value: 'İ', matches: false }]
  },
  {
    name: 'compares regex metacharacters in variables literally',
    requestContext: { 'aws:username': 'a.b' },
    policyValues: ['${aws:username}'],
    testValue: 'aXb',
    expected: true,
    explains: [{ value: '${aws:username}', matches: true, resolvedValue: 'a.b' }]
  },
  {
    name: 'does not match IAM escaped literal star',
    requestContext: {},
    policyValues: ['a${*}'],
    testValue: 'A*',
    expected: false,
    explains: [{ value: 'a${*}', matches: false }]
  },
  {
    name: 'matches unequal sigma and final sigma',
    requestContext: {},
    policyValues: ['σ'],
    testValue: 'ς',
    expected: true,
    explains: [{ value: 'σ', matches: true }]
  },
  {
    name: 'matches unequal i and dotted capital I',
    requestContext: {},
    policyValues: ['i'],
    testValue: 'İ',
    expected: true,
    explains: [{ value: 'i', matches: true }]
  },
  {
    name: 'matches unequal I and dotless i',
    requestContext: {},
    policyValues: ['I'],
    testValue: 'ı',
    expected: true,
    explains: [{ value: 'I', matches: true }]
  },
  {
    name: 'matches unequal s and long s',
    requestContext: {},
    policyValues: ['s'],
    testValue: 'ſ',
    expected: true,
    explains: [{ value: 's', matches: true }]
  },
  {
    name: 'matches unequal Deseret uppercase and lowercase',
    requestContext: {},
    policyValues: ['𐐀'],
    testValue: '𐐨',
    expected: true,
    explains: [{ value: '𐐀', matches: true }]
  },
  {
    name: 'does not match when Kelvin sign equals ASCII K ignoring case',
    requestContext: {},
    policyValues: ['K'],
    testValue: 'K',
    expected: false,
    explains: [{ value: 'K', matches: false }]
  },
  {
    name: 'does not match capital sharp s after resolving a policy variable',
    requestContext: { 'aws:username': 'ß' },
    policyValues: ['${aws:username}'],
    testValue: 'ẞ',
    expected: false,
    explains: [{ value: '${aws:username}', matches: false, resolvedValue: 'ß' }]
  },
  {
    name: 'matches when a trailing newline makes values unequal',
    requestContext: {},
    policyValues: ['abc'],
    testValue: 'abc\n',
    expected: true,
    explains: [{ value: 'abc', matches: true }]
  },
  {
    name: 'should return true if not a match',
    requestContext: {},
    policyValues: ['test'],
    testValue: 'test2',
    expected: true,
    explains: [
      {
        value: 'test',
        matches: true
      }
    ]
  },
  {
    name: 'should return false if a match',
    requestContext: {},
    policyValues: ['test'],
    testValue: 'test',
    expected: false,
    explains: [
      {
        value: 'test',
        matches: false
      }
    ]
  },
  {
    name: 'should return false if case is different',
    requestContext: {},
    policyValues: ['test'],
    testValue: 'TEST',
    expected: false,
    explains: [
      {
        value: 'test',
        matches: false
      }
    ]
  },
  {
    name: 'should replace variables and return false if a match',
    requestContext: { 'aws:username': 'Bob' },
    policyValues: ['arn:aws:iam::123456789012:user/${aws:username}'],
    testValue: 'arn:aws:iam::123456789012:user/Bob',
    expected: false,
    explains: [
      {
        value: 'arn:aws:iam::123456789012:user/${aws:username}',
        matches: false,
        resolvedValue: 'arn:aws:iam::123456789012:user/Bob'
      }
    ]
  },
  {
    name: 'should return replacement errors',
    requestContext: {},
    policyValues: ['${aws:username}'],
    testValue: 'test',
    expected: false,
    explains: [
      {
        value: '${aws:username}',
        matches: false,
        errors: [
          '{aws:username} not found in request context, and no default value provided. This will never match'
        ]
      }
    ]
  },
  {
    name: 'should return false if any value is a match',
    requestContext: {},
    policyValues: ['test1', 'test2'],
    testValue: 'TEST1',
    expected: false,
    explains: [
      {
        value: 'test1',
        matches: false
      },
      {
        value: 'test2',
        matches: true
      }
    ]
  }
]

testOperator('StringNotEqualsIgnoreCase', stringNotEqualsIgnoreCaseTests, StringNotEqualsIgnoreCase)
