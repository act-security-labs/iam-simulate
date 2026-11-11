import { iamActionDetails, iamResourceTypeDetails } from '@actsecurity/iam-data'
import { describe, expect, it, vi } from 'vitest'
import { getResourceTypesForAction } from './resourceTypes.js'

vi.mock('@actsecurity/iam-data', () => ({
  iamActionDetails: vi.fn(),
  iamResourceTypeDetails: vi.fn()
}))

describe('Lambda resource type ambiguity', () => {
  it('preserves an ambiguity between a Lambda version and an unrelated type', async () => {
    //Given two matching resource types that are not the alias/version pair
    vi.mocked(iamActionDetails).mockResolvedValue({
      name: 'Example',
      description: '',
      accessLevel: 'Read',
      conditionKeys: [],
      resourceTypes: [
        { name: 'function version', required: false, conditionKeys: [], dependentActions: [] },
        { name: 'other', required: false, conditionKeys: [], dependentActions: [] }
      ],
      dependentActions: [],
      isWildcardOnly: false
    })
    vi.mocked(iamResourceTypeDetails).mockImplementation(async (_service, key) => ({
      key,
      arn: 'arn:${Partition}:lambda:${Region}:${Account}:function:${FunctionName}:${Qualifier}',
      conditionKeys: []
    }))

    //When resolving an alias-shaped concrete Lambda ARN
    const result = await getResourceTypesForAction(
      'lambda',
      'Example',
      'arn:aws:lambda:us-east-1:123456789012:function:example:live'
    )

    //Then both matches remain so the caller can detect the ambiguity
    expect(result.map((type) => type.key)).toEqual(['function version', 'other'])
  })
})
