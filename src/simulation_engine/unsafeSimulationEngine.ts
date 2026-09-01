import { loadPolicy } from '@actsecurity/iam-policy'
import { DiscoveryContextKeyConstraints } from '../context_keys/discoveryContextKeyConstraints.js'
import { authorize, type ControlPolicies } from '../core_engine/CoreSimulatorEngine.js'
import { type EvaluationResult } from '../evaluate.js'
import { AwsRequestImpl } from '../request/request.js'
import { RequestContextImpl } from '../requestContext.js'
import { type Simulation } from './simulation.js'
import { type SimulationOptions } from './simulationOptions.js'

/**
 * Runs a simulation without input validation or context variable verification.
 * Use this if you know what you're doing.
 *
 * @param simulation The simulation to run.
 * @param simulationOptions Options for the simulation.
 * @returns The result of the simulation.
 */
export function runUnsafeSimulation(
  simulation: Simulation,
  simulationOptions: Partial<SimulationOptions>
): EvaluationResult {
  const identityPolicies = Object.values(simulation.identityPolicies).map((p) =>
    loadPolicy(p.policy, { name: p.name })
  )
  const serviceControlPolicies: ControlPolicies[] = simulation.serviceControlPolicies.map((scp) => {
    const ouId = scp.orgIdentifier
    const policies = scp.policies.map((val) => loadPolicy(val.policy, { name: val.name }))

    return {
      orgIdentifier: ouId,
      policies: policies
    }
  })

  const resourceControlPolicies: ControlPolicies[] = simulation.resourceControlPolicies.map(
    (rcp) => {
      const ouId = rcp.orgIdentifier
      const policies = rcp.policies.map((val) => loadPolicy(val.policy, { name: val.name }))

      return {
        orgIdentifier: ouId,
        policies: policies
      }
    }
  )

  const permissionBoundaries =
    simulation.permissionBoundaryPolicies?.map((val) =>
      loadPolicy(val.policy, { name: val.name })
    ) ?? undefined

  const requestContext = new RequestContextImpl(simulation.request.contextVariables)
  const request = new AwsRequestImpl(
    simulation.request.principal,
    {
      resource: simulation.request.resource.resource,
      accountId: simulation.request.resource.accountId
    },
    simulation.request.action,
    requestContext
  )

  const analysis = authorize({
    request,
    sessionPolicy: undefined,
    identityPolicies,
    serviceControlPolicies,
    resourceControlPolicies,
    resourcePolicy: simulation.resourcePolicy ? loadPolicy(simulation.resourcePolicy) : undefined,
    permissionBoundaries,
    vpcEndpointPolicies: undefined,
    simulationParameters: {
      simulationMode: 'Strict',
      discoveryContextKeyConstraints: new DiscoveryContextKeyConstraints([])
    },
    serviceSettings: {
      s3: {
        blockPublicAccess: simulation.additionalSettings?.s3?.blockPublicAccess
      }
    }
  })

  return analysis.result
}
