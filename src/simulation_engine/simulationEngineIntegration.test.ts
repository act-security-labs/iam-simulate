import { readdirSync, readFileSync, statSync } from 'fs'
import { join, resolve } from 'path'
import { describe, expect, it } from 'vitest'
import { getDenialReasons, type RequestDenial } from '../analysis/analyzeResults.js'
import type { BlockedReason, EvaluationResult } from '../evaluate.js'
import type { Simulation } from './simulation.js'
import { runSimulation, type SimulationResultType } from './simulationEngine.js'
import type { SimulationOptions } from './simulationOptions.js'

interface ExpectedResult {
  resourceType?: string
  resourcePattern?: string
  result?: string
  conditions?: unknown
}

interface IntegrationTestCase {
  name: string
  skip?: boolean
  simulation: Simulation
  simulationOptions?: Partial<SimulationOptions>
  expected: {
    resultType: SimulationResultType
    results: ExpectedResult[]
    overallResult?: EvaluationResult
    analysis?: {
      blockedBy: BlockedReason[] | null
      identityResult?: string
      permissionBoundaryResult?: string
      scpResult?: string
      denials?: RequestDenial[]
    }
  }
}

function getAllFiles(dir: string, allFiles: string[] = []): string[] {
  const files = readdirSync(dir)
  for (const file of files) {
    const filePath = join(dir, file)
    const stats = statSync(filePath)
    if (stats.isDirectory()) {
      getAllFiles(filePath, allFiles)
    } else {
      allFiles.push(filePath)
    }
  }
  return allFiles
}

function sortByResourcePattern(a: ExpectedResult, b: ExpectedResult): number {
  return (a.resourcePattern || '').localeCompare(b.resourcePattern || '')
}

describe('simulationEngineIntegration', () => {
  const testFolderPath = resolve(join(__dirname, 'simulationEngineIntegrationTests'))
  const allFiles = getAllFiles(testFolderPath)
  const pickTest: string | undefined = undefined

  for (const testFile of allFiles) {
    const relativePath = testFile.replace(testFolderPath, '').slice(1)
    describe(relativePath, () => {
      const content = readFileSync(testFile, 'utf-8')
      const testCases: IntegrationTestCase[] = JSON.parse(content)
      for (const testCase of testCases) {
        let testFunc: typeof it | typeof it.only | typeof it.skip = it
        if (pickTest === testCase.name) {
          testFunc = it.only
        } else if (testCase.skip) {
          testFunc = it.skip
        }

        testFunc(testCase.name, async () => {
          const response = await runSimulation(
            testCase.simulation,
            testCase.simulationOptions || {}
          )

          expect(response.resultType).toEqual(testCase.expected.resultType)
          if (response.resultType === 'error') {
            throw new Error('Simulation resulted in error: ' + JSON.stringify(response.errors))
          }
          if (testCase.expected.overallResult) {
            expect(response.overallResult, 'Overall Result').toEqual(
              testCase.expected.overallResult
            )
          }

          if (response.resultType === 'single') {
            const expectedAnalysis = testCase.expected.analysis
            if (expectedAnalysis) {
              const analysis = response.result.analysis
              expect(analysis.blockedBy ?? null).toEqual(expectedAnalysis.blockedBy)
              if (expectedAnalysis.identityResult !== undefined) {
                expect(analysis.identityAnalysis?.result).toEqual(expectedAnalysis.identityResult)
              }
              if (expectedAnalysis.permissionBoundaryResult !== undefined) {
                expect(analysis.permissionBoundaryAnalysis?.result).toEqual(
                  expectedAnalysis.permissionBoundaryResult
                )
              }
              if (expectedAnalysis.scpResult !== undefined) {
                expect(analysis.scpAnalysis?.result).toEqual(expectedAnalysis.scpResult)
              }
              if (expectedAnalysis.denials !== undefined) {
                expect(getDenialReasons(analysis)).toEqual(expectedAnalysis.denials)
              }
            }
            if (testCase.expected.results[0]?.resourceType !== undefined) {
              expect(response.result.resourceType).toBe(testCase.expected.results[0].resourceType)
            }
            if (testCase.expected.results[0]?.conditions) {
              expect(response.result.analysis.conditions).toEqual(
                testCase.expected.results[0].conditions
              )
            } else {
              expect(response.result.analysis.conditions, 'unexpected conditions').toBeUndefined()
            }
          }

          if (response.resultType === 'wildcard') {
            const normalizedResults: ExpectedResult[] = response.results.map((result) => ({
              resourceType: result.resourceType,
              resourcePattern: result.resourcePattern,
              result: result.analysis?.result,
              ...(result.analysis.conditions ? { conditions: result.analysis.conditions } : {})
            }))

            const expectedResults = [...testCase.expected.results]

            expect(normalizedResults.sort(sortByResourcePattern)).toEqual(
              expectedResults.sort(sortByResourcePattern)
            )
          }
        })
      }
    })
  }
})
