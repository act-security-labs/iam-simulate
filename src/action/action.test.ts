import { type ActionStatement, loadPolicy, type NotActionStatement } from '@actsecurity/iam-policy'
import { describe, expect, it } from 'vitest'
import { AwsRequestImpl } from '../request/request.js'
import { RequestContextImpl } from '../requestContext.js'
import { requestMatchesActions, requestMatchesNotActions } from './action.js'

describe('action', () => {
  describe('matchesAction', () => {
    it('should return true if the policy action is a wildcard', () => {
      //Given a policy that allows all actions
      const policy = loadPolicy({
        Statement: {
          Effect: 'Allow',
          Action: '*'
        }
      })
      const statement = policy.statements()[0]
      const actions = (statement as ActionStatement).actions()
      //And a request with an action
      const request = new AwsRequestImpl(
        'principal',
        { resource: 'resource', accountId: '111111111111' },
        's3:GetBucket',
        new RequestContextImpl({})
      )

      //When the request is checked against the policy
      const response = requestMatchesActions(request, actions)

      //Then the request should match the policy
      expect(response.matches).toBe(true)
    })

    it('should return true if the policy action matches the request action', () => {
      //Given a policy that allows the s3:GetBucket action
      const policy = loadPolicy({
        Statement: {
          Effect: 'Allow',
          Action: 's3:GetBucket'
        }
      })
      const statement = policy.statements()[0]
      const actions = (statement as ActionStatement).actions()
      //And a request with the s3:GetBucket action
      const request = new AwsRequestImpl(
        'principal',
        { resource: 'resource', accountId: '111111111111' },
        's3:GetBucket',
        new RequestContextImpl({})
      )

      //When the request is checked against the policy
      const response = requestMatchesActions(request, actions)

      //Then the request should match the policy
      expect(response.matches).toBe(true)
    })
  })

  it('should not match a wildcard service in the policy', () => {
    //Given a policy that allows all actions for the s3 service
    const policy = loadPolicy({
      Statement: {
        Effect: 'Allow',
        Action: '*:GetBucket'
      }
    })
    const statement = policy.statements()[0]
    const actions = (statement as ActionStatement).actions()
    //And a request with the s3:GetBucket action
    const request = new AwsRequestImpl(
      'principal',
      { resource: 'resource', accountId: '111111111111' },
      's3:GetBucket',
      new RequestContextImpl({})
    )

    //When the request is checked against the policy
    const response = requestMatchesActions(request, actions)

    //Then the request should not match the policy
    expect(response.matches).toBe(false)
  })

  it('should match a wildcard action in the policy', () => {
    //Given a policy that allows all actions for the s3 service
    const policy = loadPolicy({
      Statement: {
        Effect: 'Allow',
        Action: 's3:*'
      }
    })
    const statement = policy.statements()[0]
    const actions = (statement as ActionStatement).actions()

    //And a request with the s3:GetBucket action
    const request = new AwsRequestImpl(
      'principal',
      { resource: 'resource', accountId: '111111111111' },
      's3:GetBucket',
      new RequestContextImpl({})
    )

    //When the request is checked against the policy
    const response = requestMatchesActions(request, actions)

    //Then the request should match the policy
    expect(response.matches).toBe(true)
  })

  it('should request a partial Wildcard action in the policy', () => {
    //Given a policy that allows all Get actions for the s3 service
    const policy = loadPolicy({
      Statement: {
        Effect: 'Allow',
        Action: 's3:Get*'
      }
    })
    const statement = policy.statements()[0]
    const actions = (statement as ActionStatement).actions()

    //And a request with the s3:GetBucket action
    const request = new AwsRequestImpl(
      'principal',
      { resource: 'resource', accountId: '111111111111' },
      's3:GetBucket',
      new RequestContextImpl({})
    )

    //When the request is checked against the policy
    const response = requestMatchesActions(request, actions)

    //Then the request should match the policy
    expect(response.matches).toBe(true)
  })

  it('should not match a partial Wildcard action in the policy', () => {
    //Given a policy that allows all Get actions for the s3 service
    const policy = loadPolicy({
      Statement: {
        Effect: 'Allow',
        Action: 's3:Get*'
      }
    })
    const statement = policy.statements()[0]
    const actions = (statement as ActionStatement).actions()

    //And a request with the s3:GetBucket action
    const request = new AwsRequestImpl(
      'principal',
      { resource: 'resource', accountId: '111111111111' },
      's3:PutBucket',
      new RequestContextImpl({})
    )

    //When the request is checked against the policy
    const response = requestMatchesActions(request, actions)

    //Then the request should not match the policy
    expect(response.matches).toBe(false)
  })

  it('should match question mark wildcards in the actions', () => {
    //Given a policy that allows some actions for the s3 service
    const policy = loadPolicy({
      Statement: {
        Effect: 'Allow',
        Action: 's3:Get??????'
      }
    })
    const statement = policy.statements()[0]
    const actions = (statement as ActionStatement).actions()

    //And a request with the s3:GetBucket action
    const request = new AwsRequestImpl(
      'principal',
      { resource: 'resource', accountId: '111111111111' },
      's3:GetBucket',
      new RequestContextImpl({})
    )

    //When the request is checked against the policy
    const response = requestMatchesActions(request, actions)

    //Then the request should match the policy
    expect(response.matches).toBe(true)
  })

  it('should not match a different number of question mark wildcards in the actions', () => {
    //Given a policy that allows allows some actions for the s3 service
    const policy = loadPolicy({
      Statement: {
        Effect: 'Allow',
        Action: 's3:Get???'
      }
    })
    const statement = policy.statements()[0]
    const actions = (statement as ActionStatement).actions()

    //And a request with the s3:GetBucket action
    const request = new AwsRequestImpl(
      'principal',
      { resource: 'resource', accountId: '111111111111' },
      's3:GetBuckets',
      new RequestContextImpl({})
    )

    //When the request is checked against the policy
    const response = requestMatchesActions(request, actions)

    //Then the request should not match the policy
    expect(response.matches).toBe(false)
  })

  it('should return true if only one action in the policy matches the request action', () => {
    //Given a policy that allows some actions for the s3 service
    const policy = loadPolicy({
      Statement: {
        Effect: 'Allow',
        Action: ['s3:GetBucket', 's3:PutObject']
      }
    })
    const statement = policy.statements()[0]
    const actions = (statement as ActionStatement).actions()

    //And a request with the s3:GetBucket action
    const request = new AwsRequestImpl(
      'principal',
      { resource: 'resource', accountId: '111111111111' },
      's3:GetBucket',
      new RequestContextImpl({})
    )

    //When the request is checked against the policy
    const response = requestMatchesActions(request, actions)

    //Then the request should match the policy
    expect(response.matches).toBe(true)
  })

  describe('whitespace actions', () => {
    it('should not match an empty action after the colon', () => {
      //Given a policy with an empty action after the colon
      const policy = loadPolicy({
        Statement: {
          Effect: 'Allow',
          Action: 's3:'
        }
      })
      const statement = policy.statements()[0]
      const actions = (statement as ActionStatement).actions()
      //And a request with the s3:GetBucket action
      const request = new AwsRequestImpl(
        'principal',
        { resource: 'resource', accountId: '111111111111' },
        's3:GetBucket',
        new RequestContextImpl({})
      )

      //When the request is checked against the policy
      const response = requestMatchesActions(request, actions)

      //Then the request should not match the policy
      expect(response.matches).toBe(false)
    })

    it('should not match a whitespace-only action after the colon', () => {
      //Given a policy with a whitespace-only action after the colon
      const policy = loadPolicy({
        Statement: {
          Effect: 'Allow',
          Action: 's3:      '
        }
      })
      const statement = policy.statements()[0]
      const actions = (statement as ActionStatement).actions()
      //And a request with the s3:GetBucket action
      const request = new AwsRequestImpl(
        'principal',
        { resource: 'resource', accountId: '111111111111' },
        's3:GetBucket',
        new RequestContextImpl({})
      )

      //When the request is checked against the policy
      const response = requestMatchesActions(request, actions)

      //Then the request should not match the policy
      expect(response.matches).toBe(false)
    })

    it('should not match an action with trailing whitespace', () => {
      //Given a policy with trailing whitespace in the action
      const policy = loadPolicy({
        Statement: {
          Effect: 'Allow',
          Action: 's3:GetBucket   '
        }
      })
      const statement = policy.statements()[0]
      const actions = (statement as ActionStatement).actions()
      //And a request with the s3:GetBucket action
      const request = new AwsRequestImpl(
        'principal',
        { resource: 'resource', accountId: '111111111111' },
        's3:GetBucket',
        new RequestContextImpl({})
      )

      //When the request is checked against the policy
      const response = requestMatchesActions(request, actions)

      //Then the request should not match the policy
      expect(response.matches).toBe(false)
    })

    it('should not match an action with leading whitespace', () => {
      //Given a policy with leading whitespace in the action
      const policy = loadPolicy({
        Statement: {
          Effect: 'Allow',
          Action: 's3:   GetBucket'
        }
      })
      const statement = policy.statements()[0]
      const actions = (statement as ActionStatement).actions()
      //And a request with the s3:GetBucket action
      const request = new AwsRequestImpl(
        'principal',
        { resource: 'resource', accountId: '111111111111' },
        's3:GetBucket',
        new RequestContextImpl({})
      )

      //When the request is checked against the policy
      const response = requestMatchesActions(request, actions)

      //Then the request should not match the policy
      expect(response.matches).toBe(false)
    })
  })

  describe('requestMatchesNotActions', () => {
    it('should return false for a wildcard action', () => {
      //Given a policy that allows not all actions
      const policy = loadPolicy({
        Statement: {
          Effect: 'Allow',
          NotAction: '*'
        }
      })
      const statement = policy.statements()[0]
      const actions = (statement as NotActionStatement).notActions()
      //And a request with an action
      const request = new AwsRequestImpl(
        'principal',
        { resource: 'resource', accountId: '111111111111' },
        's3:GetBucket',
        new RequestContextImpl({})
      )

      //When the request is checked against the policy
      const response = requestMatchesNotActions(request, actions)

      //Then the request should not match the policy
      expect(response.matches).toBe(false)
    })

    it('should return false if the policy action matches the request action', () => {
      //Given a policy that allows not the s3:GetBucket action
      const policy = loadPolicy({
        Statement: {
          Effect: 'Allow',
          NotAction: 's3:GetBucket'
        }
      })
      const statement = policy.statements()[0]
      const actions = (statement as NotActionStatement).notActions()
      //And a request with the s3:GetBucket action
      const request = new AwsRequestImpl(
        'principal',
        { resource: 'resource', accountId: '111111111111' },
        's3:GetBucket',
        new RequestContextImpl({})
      )

      //When the request is checked against the policy
      const response = requestMatchesNotActions(request, actions)

      //Then the request should not match the policy
      expect(response.matches).toBe(false)
    })

    it('should return true for an empty action after the colon', () => {
      //Given a policy with NotAction with an empty action after the colon
      const policy = loadPolicy({
        Statement: {
          Effect: 'Allow',
          NotAction: 's3:'
        }
      })
      const statement = policy.statements()[0]
      const actions = (statement as NotActionStatement).notActions()
      //And a request with the s3:GetBucket action
      const request = new AwsRequestImpl(
        'principal',
        { resource: 'resource', accountId: '111111111111' },
        's3:GetBucket',
        new RequestContextImpl({})
      )

      //When the request is checked against the policy
      const response = requestMatchesNotActions(request, actions)

      //Then the request should match because the empty action never matches
      expect(response.matches).toBe(true)
    })

    it('should return true for a whitespace-only action after the colon', () => {
      //Given a policy with NotAction with whitespace-only after the colon
      const policy = loadPolicy({
        Statement: {
          Effect: 'Allow',
          NotAction: 's3:      '
        }
      })
      const statement = policy.statements()[0]
      const actions = (statement as NotActionStatement).notActions()
      //And a request with the s3:GetBucket action
      const request = new AwsRequestImpl(
        'principal',
        { resource: 'resource', accountId: '111111111111' },
        's3:GetBucket',
        new RequestContextImpl({})
      )

      //When the request is checked against the policy
      const response = requestMatchesNotActions(request, actions)

      //Then the request should match because the whitespace action never matches
      expect(response.matches).toBe(true)
    })

    it('should return true for an action with trailing whitespace', () => {
      //Given a policy with NotAction with trailing whitespace
      const policy = loadPolicy({
        Statement: {
          Effect: 'Allow',
          NotAction: 's3:GetBucket   '
        }
      })
      const statement = policy.statements()[0]
      const actions = (statement as NotActionStatement).notActions()
      //And a request with the s3:GetBucket action
      const request = new AwsRequestImpl(
        'principal',
        { resource: 'resource', accountId: '111111111111' },
        's3:GetBucket',
        new RequestContextImpl({})
      )

      //When the request is checked against the policy
      const response = requestMatchesNotActions(request, actions)

      //Then the request should match because the whitespace action never matches
      expect(response.matches).toBe(true)
    })

    it('should return true for an action with leading whitespace', () => {
      //Given a policy with NotAction with leading whitespace
      const policy = loadPolicy({
        Statement: {
          Effect: 'Allow',
          NotAction: 's3:   GetBucket'
        }
      })
      const statement = policy.statements()[0]
      const actions = (statement as NotActionStatement).notActions()
      //And a request with the s3:GetBucket action
      const request = new AwsRequestImpl(
        'principal',
        { resource: 'resource', accountId: '111111111111' },
        's3:GetBucket',
        new RequestContextImpl({})
      )

      //When the request is checked against the policy
      const response = requestMatchesNotActions(request, actions)

      //Then the request should match because the whitespace action never matches
      expect(response.matches).toBe(true)
    })
  })
})
