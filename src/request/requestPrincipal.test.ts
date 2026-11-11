import { describe, expect, it } from 'vitest'
import { anonymousPrincipal } from '../simulation_engine/simulation.js'
import { requestPrincipalFromInput } from './requestPrincipal.js'

describe('requestPrincipalFromInput', () => {
  it('creates an anonymous request principal', () => {
    //Given an anonymous principal input
    const principalInput = anonymousPrincipal

    //When the request principal is created
    const principal = requestPrincipalFromInput(principalInput)

    //Then it represents an anonymous request
    expect(principal.kind()).toEqual('Anonymous')
    expect(principal.isAnonymous()).toEqual(true)
    expect('accountId' in principal).toEqual(false)
    expect('value' in principal).toEqual(false)
  })

  it('creates a string request principal with an account id for ARN values', () => {
    //Given an ARN principal input
    const principalInput = 'arn:aws:iam::123456789012:user/Alice'

    //When the request principal is created
    const principal = requestPrincipalFromInput(principalInput)

    //Then it represents the string principal
    expect(principal.kind()).toEqual('Authenticated')
    expect(principal.isAnonymous()).toEqual(false)
    expect(principal.accountId()).toEqual('123456789012')
    expect(principal.value()).toEqual(principalInput)
  })

  it('does not treat the CloudFront OAI policy ARN as an account identifier', () => {
    //Given an OAI policy principal whose ARN does not encode its owner account
    const principalInput = 'arn:aws:iam::cloudfront:user/CloudFront Origin Access Identity E123'

    //When the request principal is created
    const principal = requestPrincipalFromInput(principalInput)

    //Then the owner is unknown and the original policy principal remains available
    expect(principal.accountId()).toBeUndefined()
    expect(principal.value()).toEqual(principalInput)
  })

  it('returns undefined account id for non-ARN string values', () => {
    //Given a non-ARN principal input
    const principalInput = 'not-an-arn'

    //When the request principal is created
    const principal = requestPrincipalFromInput(principalInput)

    //Then no account id is parsed
    expect(principal.accountId()).toBeUndefined()
  })

  it('throws a clear error for malformed object principals', () => {
    //Given a malformed principal input
    const principalInput = { type: 'User' }

    //When the request principal is created
    const createPrincipal = () => requestPrincipalFromInput(principalInput as any)

    //Then a clear validation error is thrown
    expect(createPrincipal).toThrow('invalid.principal')
  })

  it('throws a clear error for anonymous principals with extra fields', () => {
    //Given an anonymous principal input with extra fields
    const principalInput = { type: 'Anonymous', accountId: '123456789012' }

    //When the request principal is created
    const createPrincipal = () => requestPrincipalFromInput(principalInput as any)

    //Then a clear validation error is thrown
    expect(createPrincipal).toThrow('invalid.principal')
  })
})
