import { describe, expect, it } from 'vitest'
import { RequestContextImpl } from './requestContext.js'

describe('RequestContextImpl Unicode context-key identity', () => {
  it('retrieves a final-sigma context key using the equivalent sigma name', () => {
    //Given a context key whose suffix uses final sigma
    const context = new RequestContextImpl({ 'aws:ResourceTag/ς': 'value' })

    //When looking up the key using ordinary sigma
    const exists = context.contextKeyExists('aws:ResourceTag/σ')

    //Then the name and value refer to the original entry
    expect(exists).toBe(true)
    expect(context.contextKeyValue('aws:ResourceTag/σ')).toMatchObject({
      name: 'aws:ResourceTag/ς',
      value: 'value'
    })
  })

  it('uses the later value for equivalent keys and keeps accented names distinct', () => {
    //Given equivalent sigma names and distinct accented names
    const context = new RequestContextImpl({
      'aws:ResourceTag/σ': 'first',
      'aws:ResourceTag/ς': 'last',
      'aws:ResourceTag/cafe': 'plain',
      'aws:ResourceTag/café': 'accented'
    })

    //When looking up each key
    //Then case-equivalent keys share the last value without merging accent differences
    expect(context.contextKeyValue('aws:ResourceTag/σ')).toMatchObject({ value: 'last' })
    expect(context.contextKeyValue('aws:ResourceTag/cafe')).toMatchObject({ value: 'plain' })
    expect(context.contextKeyValue('aws:ResourceTag/café')).toMatchObject({ value: 'accented' })
  })
})
