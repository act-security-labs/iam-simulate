import { loadPolicy } from '@actsecurity/iam-policy'
import { readdirSync, readFileSync, statSync } from 'fs'
import { join, resolve } from 'path'
import { describe, expect, it } from 'vitest'
import { DiscoveryContextKeyConstraints } from '../context_keys/discoveryContextKeyConstraints.js'
import { AwsRequestImpl } from '../request/request.js'
import { RequestContextImpl } from '../requestContext.js'
import {
  type AuthorizationRequest,
  authorize,
  type SimulationParameters
} from './CoreSimulatorEngine.js'

function getAllFiles(dir: string, allFiles: string[] = []): string[] {
  const files = readdirSync(dir)

  files.forEach((file) => {
    const filePath = join(dir, file)
    const stats = statSync(filePath)

    if (stats.isDirectory()) {
      // Recursively read directory
      getAllFiles(filePath, allFiles)
    } else {
      // Add file to the list
      allFiles.push(filePath)
    }
  })

  return allFiles
}

const defaultRcp = loadPolicy(
  {
    Version: '2012-10-17',
    Statement: [
      {
        Effect: 'Allow',
        Action: '*',
        Resource: '*'
      }
    ]
  },
  { name: 'RCPFullAccess' }
)

const conditionKeysToVerify = [
  'scp',
  'rcp',
  'session',
  'identity',
  'resource',
  'permissionBoundary',
  'endpointPolicy'
]

describe('coreSimulatorEngine', () => {
  const testFolderPath = resolve(join(__dirname, 'coreEngineTests'))
  const allFiles = getAllFiles(testFolderPath)
  const pickTest: string | undefined = undefined

  for (const testFile of allFiles) {
    const relativePath = testFile.replace(testFolderPath, '').slice(1)
    describe(relativePath, () => {
      const content = readFileSync(testFile, 'utf-8')
      const testCases = JSON.parse(content)
      for (const testCase of testCases) {
        let testFunc: typeof it | typeof it.only | typeof it.skip = it
        if (pickTest === testCase.name) {
          testFunc = it.only
        } else if (testCase.skip) {
          testFunc = it.skip
        }
        testFunc(testCase.name, () => {
          //Given the request
          const { principal, resource, action, context, wildcardOnlyAction } = testCase.request
          const request = new AwsRequestImpl(
            principal,
            resource,
            action,
            new RequestContextImpl(context),
            wildcardOnlyAction
          )
          // And Policies
          const identityPolicies = testCase.identityPolicies.map((p: any, idx: number) =>
            loadPolicy(p, { name: idx.toString() })
          )

          const sessionPolicy = testCase.sessionPolicy
            ? loadPolicy(testCase.sessionPolicy, { name: 'SessionPolicy' })
            : undefined

          const serviceControlPolicies = (testCase.serviceControlPolicies || []).map((scp: any) => {
            return {
              orgIdentifier: scp.orgIdentifier,
              policies: scp.policies.map((p: any, idx: number) =>
                loadPolicy(p, { name: idx.toString() })
              )
            }
          })

          const resourceControlPolicies = (testCase.resourceControlPolicies || []).map(
            (rcp: any, idx: number) => {
              return {
                orgIdentifier: rcp.orgIdentifier,
                //We add a default allow all rcp to every level of the org, just like AWS does.
                policies: [
                  defaultRcp,
                  ...rcp.policies.map((p: any) => loadPolicy(p, { name: idx.toString() }))
                ]
              }
            }
          )

          const resourcePolicy = testCase.resourcePolicy
            ? loadPolicy(testCase.resourcePolicy, { name: 'ResourcePolicy' })
            : undefined

          const permissionBoundaries = testCase.permissionBoundaries
            ? testCase.permissionBoundaries.map((p: any, idx: number) =>
                loadPolicy(p, { name: idx.toString() })
              )
            : undefined

          const vpcEndPointPolicies = testCase.endpointPolicies
            ? testCase.endpointPolicies.map((p: any, idx: number) =>
                loadPolicy(p, { name: idx.toString() })
              )
            : undefined

          const simulationParameters: SimulationParameters = {
            simulationMode: testCase.simulation?.mode || 'Strict',
            discoveryContextKeyConstraints: new DiscoveryContextKeyConstraints(
              testCase.simulation?.discoveryContextKeyConstraints || []
            )
          }

          //In an authorization request
          const authorizationRequest: AuthorizationRequest = {
            request,
            sessionPolicy,
            identityPolicies,
            serviceControlPolicies,
            resourceControlPolicies,
            resourcePolicy,
            permissionBoundaries,
            vpcEndpointPolicies: vpcEndPointPolicies,
            simulationParameters
          }

          // When the request is authorized
          const analysis = authorize(authorizationRequest)

          // Then the result should match the expected result
          const expected = testCase.expected
          expect(analysis.result).toEqual(expected.response)

          if (expected.ignoredRoleSessionName) {
            expect(analysis.ignoredRoleSessionName).toEqual(expected.ignoredRoleSessionName)
          } else {
            expect(analysis.ignoredRoleSessionName).toBeFalsy()
          }

          if (expected.conditions) {
            expect(analysis.conditions).toEqual(expected.conditions)
          } else {
            expect(analysis.conditions, 'unexpected conditions').toBeUndefined()
          }

          if (expected.ignoredConditions) {
            for (const key of conditionKeysToVerify) {
              const actualAllow = (analysis.ignoredConditions as any)?.[key]?.allow
              const actualDeny = (analysis.ignoredConditions as any)?.[key]?.deny
              if (expected.ignoredConditions[key]?.allow) {
                expect(actualAllow).toBeDefined()
                const actualAllows = actualAllow
                expect(actualAllows).toEqual(expected.ignoredConditions[key]?.allow)
              } else {
                expect(actualAllow).toEqual(undefined)
              }

              if (expected.ignoredConditions[key]?.deny) {
                expect(actualDeny).toBeDefined()
                const actualDenies = actualDeny
                expect(actualDenies).toEqual(expected.ignoredConditions[key]?.deny)
              } else {
                expect(actualDeny).toEqual(undefined)
              }
            }
          } else {
            let ignoredConditionsUndefinedOrEmpty = true
            if (analysis.ignoredConditions) {
              for (const key of conditionKeysToVerify) {
                const actualAllow = (analysis.ignoredConditions as any)?.[key]?.allow
                const actualDeny = (analysis.ignoredConditions as any)?.[key]?.deny
                if (actualAllow && actualAllow.length > 0) {
                  ignoredConditionsUndefinedOrEmpty = false
                }
                if (actualDeny && actualDeny.length > 0) {
                  ignoredConditionsUndefinedOrEmpty = false
                }
              }
            }
            expect(
              ignoredConditionsUndefinedOrEmpty,
              JSON.stringify(analysis.ignoredConditions)
            ).toBe(true)
          }

          // Check blockedBy
          const expectedBlockedBy = expected.blockedBy
          const actualBlockedBy = analysis.blockedBy

          if (expectedBlockedBy && !actualBlockedBy) {
            expect.fail(
              `Expected blockedBy to be ${JSON.stringify(expectedBlockedBy)} but was undefined`
            )
          } else if (!expectedBlockedBy && actualBlockedBy) {
            expect.fail(
              `Expected blockedBy to be undefined but was ${JSON.stringify(actualBlockedBy)}`
            )
          } else if (expectedBlockedBy && actualBlockedBy) {
            const sortedExpected = [...expectedBlockedBy].sort()
            const sortedActual = [...actualBlockedBy].sort()
            expect(sortedActual, 'blockedBy mismatch').toEqual(sortedExpected)
          }
        })
      }
    })
  }
})
