import {
  getAllGlobalConditionKeys,
  iamActionDetails,
  iamResourceTypeDetails,
  type ResourceType
} from '@actsecurity/iam-data'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { allowedContextKeysForRequest } from './contextKeys.js'

vi.mock('@actsecurity/iam-data')

beforeEach(() => {
  vi.resetAllMocks()
  vi.mocked(getAllGlobalConditionKeys).mockReturnValue(['aws:PrincipalTag', 'aws:SourceVpc'])
})

describe('allowedContextKeysForRequest', () => {
  it('should return the conditions keys for an action when it is a wildcard', async () => {
    //Given a request for an action
    const service = 's3'
    const action = 'ListTagsForResource'

    //And there are condition keys for the action
    vi.mocked(iamActionDetails).mockResolvedValue({
      conditionKeys: ['aws:RequestTag', 'aws:ResourceTag'],
      isWildcardOnly: false,
      accessLevel: 'Read',
      dependentActions: [],
      resourceTypes: [],
      description: 'List the tags for a resource',
      name: 'ListTagsForResource'
    })

    //When calling allowedContextKeysForRequest
    const result = await allowedContextKeysForRequest(
      service,
      action,
      'arn:aws:s3:us-east-1:12345:access-grants/default',
      false,
      undefined
    )

    //Then it should return the expected context keys
    expect(result).toEqual(
      expect.arrayContaining([
        'aws:requesttag',
        'aws:resourcetag',
        ...getAllGlobalConditionKeys().map((k) => k.toLowerCase())
      ])
    )
  })

  it('should return the context keys for a single resource type', async () => {
    //Given a request for an action
    const service = 's3'
    const action = 'GetObject'

    //And there are condition keys for the action
    vi.mocked(iamActionDetails).mockResolvedValue({
      conditionKeys: ['aws:RequestTag', 'aws:ResourceTag'],
      isWildcardOnly: false,
      accessLevel: 'Read',
      dependentActions: [],
      resourceTypes: [
        {
          name: 'object',
          dependentActions: [],
          required: true,
          conditionKeys: ['aws:ObjectFoo', 'aws:ObjectBar']
        }
      ],
      description: 'Get an object',
      name: 'GetObject'
    })

    vi.mocked(iamResourceTypeDetails).mockResolvedValue({
      key: 'object',
      arn: 'arn:${Partition}:s3:::${BucketName}/${ObjectName}',
      conditionKeys: ['aws:ObjectFoo', 'aws:ObjectBar']
    })

    //When calling allowedContextKeysForRequest
    const result = await allowedContextKeysForRequest(
      service,
      action,
      'arn:aws:s3:::muh-bucket/object-123',
      false,
      undefined
    )

    //Then it should have the global keys, the keys for the action, and the keys for the resource type
    expect(result).toEqual(
      expect.arrayContaining([
        'aws:objectfoo',
        'aws:objectbar',
        'aws:requesttag',
        'aws:resourcetag',
        ...getAllGlobalConditionKeys().map((k) => k.toLowerCase())
      ])
    )
  })

  it('should include condition keys from the resource type definition when the action resource type entry has none', async () => {
    //Given a KMS action whose per-action resource type entry has no condition keys
    const service = 'kms'
    const action = 'CreateGrant'
    vi.mocked(iamActionDetails).mockResolvedValue({
      conditionKeys: ['kms:ViaService'],
      isWildcardOnly: false,
      accessLevel: 'Permissions management',
      dependentActions: [],
      resourceTypes: [
        {
          name: 'key',
          dependentActions: [],
          required: true,
          conditionKeys: []
        }
      ],
      description: 'Adds a grant to a KMS key',
      name: 'CreateGrant'
    })

    //And the resolved resource type definition has keys that apply to all key resources
    vi.mocked(iamResourceTypeDetails).mockResolvedValue({
      key: 'key',
      arn: 'arn:${Partition}:kms:${Region}:${Account}:key/${KeyId}',
      conditionKeys: ['kms:ResourceAliases', 'kms:KeySpec']
    })

    //When calling allowedContextKeysForRequest
    const result = await allowedContextKeysForRequest(
      service,
      action,
      'arn:aws:kms:us-east-1:111111111111:key/abcd-1234',
      false,
      undefined
    )

    //Then it should include action, resource type definition, and global keys
    expect(result).toEqual(
      expect.arrayContaining([
        'kms:resourcealiases',
        'kms:keyspec',
        'kms:viaservice',
        ...getAllGlobalConditionKeys().map((k) => k.toLowerCase())
      ])
    )
  })

  it('should include condition keys from a suggested resource type definition', async () => {
    //Given a KMS action whose per-action resource type entry has no condition keys
    const service = 'kms'
    const action = 'CreateGrant'
    vi.mocked(iamActionDetails).mockResolvedValue({
      conditionKeys: ['kms:ViaService'],
      isWildcardOnly: false,
      accessLevel: 'Permissions management',
      dependentActions: [],
      resourceTypes: [
        {
          name: 'key',
          dependentActions: [],
          required: true,
          conditionKeys: []
        }
      ],
      description: 'Adds a grant to a KMS key',
      name: 'CreateGrant'
    })

    //And the caller has already resolved the resource type definition
    const suggestedResourceType = {
      key: 'key',
      arn: 'arn:${Partition}:kms:${Region}:${Account}:key/${KeyId}',
      conditionKeys: ['kms:ResourceAliases', 'kms:KeySpec']
    }

    //When calling allowedContextKeysForRequest with the suggested resource type
    const result = await allowedContextKeysForRequest(
      service,
      action,
      'arn:aws:kms:us-east-1:111111111111:key/abcd-1234',
      false,
      suggestedResourceType
    )

    //Then it should include action, resource type definition, and global keys
    expect(result).toEqual(
      expect.arrayContaining([
        'kms:resourcealiases',
        'kms:keyspec',
        'kms:viaservice',
        ...getAllGlobalConditionKeys().map((k) => k.toLowerCase())
      ])
    )
  })

  it('should treat missing resource type condition keys as empty', async () => {
    //Given IAM data returns a resource type definition without conditionKeys
    const service = 'iam'
    const action = 'TagGroup'
    vi.mocked(iamActionDetails).mockResolvedValue({
      conditionKeys: ['iam:PermissionsBoundary'],
      isWildcardOnly: false,
      accessLevel: 'Tagging',
      dependentActions: [],
      resourceTypes: [
        {
          name: 'group',
          dependentActions: [],
          required: true,
          conditionKeys: ['iam:ResourceTag/${TagKey}']
        }
      ],
      description: 'Adds tags to an IAM group',
      name: 'TagGroup'
    })
    vi.mocked(iamResourceTypeDetails).mockResolvedValue({
      key: 'group',
      arn: 'arn:${Partition}:iam::${Account}:group/${GroupName}'
    } as ResourceType)

    //When calling allowedContextKeysForRequest
    const result = await allowedContextKeysForRequest(
      service,
      action,
      'arn:aws:iam::111111111111:group/example',
      false,
      undefined
    )

    //Then missing resource type condition keys do not prevent action and per-action resource keys from being returned
    expect(result).toEqual([
      'iam:resourcetag/${tagkey}',
      'iam:permissionsboundary',
      ...getAllGlobalConditionKeys().map((k) => k.toLowerCase())
    ])
  })

  it('should treat missing suggested resource type condition keys as empty', async () => {
    //Given a suggested resource type definition without conditionKeys
    const service = 'iam'
    const action = 'TagGroup'
    vi.mocked(iamActionDetails).mockResolvedValue({
      conditionKeys: ['iam:PermissionsBoundary'],
      isWildcardOnly: false,
      accessLevel: 'Tagging',
      dependentActions: [],
      resourceTypes: [
        {
          name: 'group',
          dependentActions: [],
          required: true,
          conditionKeys: ['iam:ResourceTag/${TagKey}']
        }
      ],
      description: 'Adds tags to an IAM group',
      name: 'TagGroup'
    })
    const suggestedResourceType = {
      key: 'group',
      arn: 'arn:${Partition}:iam::${Account}:group/${GroupName}'
    } as ResourceType

    //When calling allowedContextKeysForRequest with the suggested resource type
    const result = await allowedContextKeysForRequest(
      service,
      action,
      'arn:aws:iam::111111111111:group/example',
      false,
      suggestedResourceType
    )

    //Then action and per-action resource keys are returned without requiring resource type condition keys
    expect(result).toEqual([
      'iam:resourcetag/${tagkey}',
      'iam:permissionsboundary',
      ...getAllGlobalConditionKeys().map((k) => k.toLowerCase())
    ])
  })

  it.todo('should search for the specific resource type for an action')

  it('should remove s3 ABAC keys if the bucket does not have ABAC enabled', async () => {
    //Given a request for an S3 action
    const service = 's3'
    const action = 'GetObject'

    //And there are condition keys for the action including ABAC keys
    vi.mocked(iamActionDetails).mockResolvedValue({
      conditionKeys: ['aws:RequestTag', 'aws:ResourceTag/${TagKey}'],
      isWildcardOnly: false,
      accessLevel: 'Read',
      dependentActions: [],
      resourceTypes: [
        {
          name: 'object',
          dependentActions: [],
          required: true,
          conditionKeys: ['aws:ResourceTag/${TagKey}', 's3:BucketTag/${TagKey}']
        }
      ],
      description: 'Get an object',
      name: 'GetObject'
    })

    vi.mocked(iamResourceTypeDetails).mockResolvedValue({
      key: 'object',
      arn: 'arn:${Partition}:s3:::${BucketName}/${ObjectName}',
      conditionKeys: ['aws:ResourceTag/${TagKey}', 's3:BucketTag/${TagKey}']
    })

    //When calling allowedContextKeysForRequest with bucketAbacEnabled set to false
    const result = await allowedContextKeysForRequest(
      service,
      action,
      'arn:aws:s3:::muh-bucket/object-123',
      false,
      undefined
    )

    //Then it should not include the S3 ABAC keys
    expect(result).not.toContain('aws:resourcetag/${tagkey}')
    expect(result).not.toContain('s3:buckettag/${tagkey}')
    //And it should include other keys
    expect(result).toContain('aws:requesttag')
  })

  it('should allow s3 ABAC keys if the bucket has ABAC enabled', async () => {
    //Given a request for an S3 action
    const service = 's3'
    const action = 'GetObject'

    //And there are condition keys for the action including ABAC keys
    vi.mocked(iamActionDetails).mockResolvedValue({
      conditionKeys: ['aws:RequestTag', 'aws:ResourceTag/${TagKey}'],
      isWildcardOnly: false,
      accessLevel: 'Read',
      dependentActions: [],
      resourceTypes: [
        {
          name: 'object',
          dependentActions: [],
          required: true,
          conditionKeys: ['aws:ResourceTag/${TagKey}', 's3:BucketTag/${TagKey}']
        }
      ],
      description: 'Get an object',
      name: 'GetObject'
    })

    vi.mocked(iamResourceTypeDetails).mockResolvedValue({
      key: 'object',
      arn: 'arn:${Partition}:s3:::${BucketName}/${ObjectName}',
      conditionKeys: ['aws:ResourceTag/${TagKey}', 's3:BucketTag/${TagKey}']
    })

    //When calling allowedContextKeysForRequest with bucketAbacEnabled set to true
    const result = await allowedContextKeysForRequest(
      service,
      action,
      'arn:aws:s3:::muh-bucket/object-123',
      true,
      undefined
    )

    //Then it should include the S3 ABAC keys
    expect(result).toContain('aws:resourcetag/${tagkey}')
    expect(result).toContain('s3:buckettag/${tagkey}')
    //And it should include other keys
    expect(result).toContain('aws:requesttag')
  })
})
