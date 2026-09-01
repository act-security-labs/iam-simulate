# IAM Simulate

[![NPM Version](https://img.shields.io/npm/v/@actsecurity/iam-simulate.svg?logo=nodedotjs)](https://www.npmjs.com/package/@actsecurity/iam-simulate) [![License: AGPL v3](https://img.shields.io/github/license/act-security-labs/iam-simulate)](LICENSE.txt) [![GuardDog](https://github.com/act-security-labs/iam-simulate/actions/workflows/guarddog.yml/badge.svg)](https://github.com/act-security-labs/iam-simulate/actions/workflows/guarddog.yml) [![Known Vulnerabilities](https://snyk.io/test/github/act-security-labs/iam-simulate/badge.svg?targetFile=package.json&style=flat-square)](https://snyk.io/test/github/act-security-labs/iam-simulate?targetFile=package.json)

An AWS IAM Simulator and Policy Tester built as a Node/Typescript library.

The simulator currently supports these features of AWS IAM

### IAM Feature Support

- Identity Policies
- Resource Policies
- Service Control Policies
- Resource Control Policies
- Permission Boundaries
- All [AWS Condition Operators](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html)
- Same Account and Cross Account Requests
- Custom trust behavior for IAM Trust Policies and KMS Key Policies

### Request Validation

iam-simulate will automatically validate inputs including

- IAM policies using [iam-policy](https://github.com/act-security-labs/iam-policy)
- IAM Actions using [iam-data](https://github.com/act-security-labs/iam-data)
- The resource ARN against allowed resource types for the action
- The context keys allowed for the action/resource and their types.

Currently all [global condition keys](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html) are allowed for all requests which is not strictly true. More validation will be added in the future.

### Explanation

iam-simulate will detail which statements were decisive in the final decision to allow or deny a request.

It will also return "explains" for each statement that was evaluated, detailing why that statement applied to the request or not.

### Features Coming Soon

- Session Policies
- Validation of Global Condition Keys for each action
- Automatically populating context keys from the request such as `aws:PrincipalServiceName`

### Anonymous Requests

Use `anonymousPrincipal` to simulate unsigned requests, such as public S3 object access granted by a bucket policy. Anonymous requests do not have identity policies, session policies, permission boundaries, or SCPs; those principal-side policy inputs are rejected by `runSimulation`.

```typescript
import { anonymousPrincipal, runSimulation, type Simulation } from '@actsecurity/iam-simulate'

const simulation: Simulation = {
  request: {
    principal: anonymousPrincipal,
    action: 's3:GetObject',
    resource: {
      resource: 'arn:aws:s3:::public-bucket/file.txt',
      accountId: '123456789012'
    },
    contextVariables: {}
  },
  identityPolicies: [],
  serviceControlPolicies: [],
  resourceControlPolicies: [],
  resourcePolicy: {
    Version: '2012-10-17',
    Statement: [
      {
        Effect: 'Allow',
        Principal: '*',
        Action: 's3:GetObject',
        Resource: 'arn:aws:s3:::public-bucket/*'
      }
    ]
  }
}

const response = await runSimulation(simulation, {})
```

### S3 Block Public Access

For S3 requests, callers can provide the effective `RestrictPublicBuckets` setting with `additionalSettings.s3.blockPublicAccess`. iam-simulate does not fetch or determine this setting; provide `true` only when S3 Block Public Access should apply for the bucket/account being simulated.

```typescript
const simulation: Simulation = {
  // request and policies...
  additionalSettings: {
    s3: {
      blockPublicAccess: true
    }
  }
}
```

When enabled, public S3 bucket policies can block anonymous and cross-account access with `blockedBy: ['s3-bpa']`.

## Installation

```bash
npm install @actsecurity/iam-simulate
```

## Usage

```typescript
import { runSimulation, type Simulation } from '@actsecurity/iam-simulate'

const simulation: Simulation = {
  identityPolicies: [
    {
      name: 'userpolicy',
      policy: {
        Version: '2012-10-17',
        Statement: [
          {
            Effect: 'Allow',
            Action: ['s3:GetObject'],
            Resource: ['arn:aws:s3:::mybucket/*']
          }
        ]
      }
    }
  ],
  serviceControlPolicies: [
    {
      orgIdentifier: 'ou-12345',
      policies: [
        {
          name: 'AllowAll',
          policy: {
            Version: '2012-10-17',
            Statement: [
              {
                Effect: 'Allow',
                Action: '*',
                Resource: '*'
              }
            ]
          }
        }
      ]
    }
  ],
  /*
    The default RCP `RCPFullAWSAccess` is always applied implicitly and you do not need to include it here. https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_rcps_examples.html#example-rcp-full-aws-access
  */
  resourceControlPolicies: [
    {
      orgIdentifier: 'o-123456789012',
      policies: [
        {
          name: 'EnforceSecureTransport',
          policy: {
            Version: '2012-10-17',
            Statement: [
              {
                Sid: 'EnforceSecureTransport',
                Effect: 'Deny',
                Principal: '*',
                Action: ['sts:*', 's3:*', 'sqs:*', 'secretsmanager:*', 'kms:*'],
                Resource: '*',
                Condition: {
                  BoolIfExists: {
                    'aws:SecureTransport': 'false'
                  }
                }
              }
            ]
          }
        }
      ]
    }
  ],
  resourcePolicy: {
    Version: '2012-10-17',
    Statement: [
      {
        Effect: 'Allow',
        Action: ['s3:GetObject'],
        Resource: ['arn:aws:s3:::mybucket/*'],
        Principal: 'aws:arn:iam::123456789012:root',
        Condition: {
          StringEquals: {
            'aws:PrincipalOrgID': 'o-123456789012'
          }
        }
      }
    ]
  },
  request: {
    action: 's3:GetObject',
    principal: 'arn:aws:iam::123456789012:user/username',
    resource: {
      accountId: '123456789012',
      resource: 'arn:aws:s3:::mybucket/file.txt'
    },
    contextVariables: {
      'aws:PrincipalOrgID': 'o-123456789012'
    }
  }
}

`runSimulation` returns a discriminated union with `resultType`:

- `resultType: 'error'` includes `errors` and no simulation results.
- `resultType: 'single'` includes `overallResult` and a single `result`.
- `resultType: 'wildcard'` includes `overallResult` and `results` for each matching pattern.

const response = await runSimulation(simulation, {})
//Check for validation errors (errors are returned at the response level):
if (response.resultType === 'error') {
  console.log(response.errors.message)
  console.log(JSON.stringify(response.errors, null, 2))
}

//The simulation ran successfully
if (response.resultType === 'single') {
  const result = response.result
  console.log(response.overallResult) // 'Allowed', 'ExplicitlyDenied', or 'ImplicitlyDenied'
  console.log(result.analysis?.result)

  //Output the identity statements that allowed the request
  const identityAllowExplains =
    result?.analysis?.identityAnalysis?.allowStatements.map((s) => s.explain) || []
  //Show which statements applied and exactly how.
  for (const explain of identityAllowExplains) {
    console.log(explain)
  }
}

if (response.resultType === 'wildcard') {
  console.log(response.overallResult)
  for (const result of response.results) {
    console.log(result.resourcePattern, result.analysis?.result)
  }
}
```

This would output an explain that shows how the identity statement was evaluated:

```javascript
{
  effect: 'Allow',
  identifier: '1',
  matches: true,
  actionMatch: true,
  principalMatch: 'Match',
  resourceMatch: true,
  conditionMatch: true,
  resources: [
    {
      resource: 'arn:aws:s3:::mybucket/*',
      matches: true,
    }
  ],
  actions: [ { action: 's3:GetObject', matches: true } ],
}
```
