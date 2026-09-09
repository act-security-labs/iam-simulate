import { iamActionExists, iamServiceExists, type ResourceType } from '@actsecurity/iam-data'
import {
  isValidatedPolicy,
  loadPolicy,
  validateEndpointPolicy,
  validateIdentityPolicy,
  validateResourceControlPolicy,
  validateResourcePolicy,
  validateServiceControlPolicy,
  type ValidationError
} from '@actsecurity/iam-policy'
import { isAssumedRoleArn, isFederatedUserArn, isIamRoleArn } from '@actsecurity/iam-utils'
import { mergeAllowedConditionExpressions } from '../analysis/allowedConditions.js'
import { isConditionKeyArray } from '../context_keys/contextKeyTypes.js'
import { normalizeContextKeyCase, typeForContextKey } from '../context_keys/contextKeys.js'
import { DiscoveryContextKeyConstraints } from '../context_keys/discoveryContextKeyConstraints.js'
import {
  authorize,
  type ControlPolicies,
  type PolicyWithName,
  type SimulationMode,
  validSimulationModes
} from '../core_engine/CoreSimulatorEngine.js'
import { type EvaluationResult, type RequestAnalysis } from '../evaluate.js'
import { AwsRequestImpl } from '../request/request.js'
import { RequestContextImpl } from '../requestContext.js'
import { isWildcardOnlyAction } from '../util.js'
import { allowedContextKeysForRequest } from './contextKeys.js'
import { calculateOverallResult } from './overallResult.js'
import { getMatchingResourceStringsForPolicies } from './policyResources.js'
import { expandShortArn } from '../util/resourceStrings.js'
import { getResourceTypesForAction } from './resourceTypes.js'
import {
  isAnonymousRequestPrincipal,
  isSimulationRequestPrincipal,
  type Simulation
} from './simulation.js'
import { type SimulationOptions } from './simulationOptions.js'

const DEFAULT_RCP = {
  arn: 'arn:aws:organizations::aws:policy/resource_control_policy/p-RCPFullAWSAccess',
  policy: {
    Version: '2012-10-17',
    Statement: [
      {
        Effect: 'Allow',
        Principal: '*',
        Action: '*',
        Resource: '*'
      }
    ]
  }
}

export interface SimulationErrors {
  sessionPolicyErrors?: ValidationError[]
  identityPolicyErrors?: Record<string, ValidationError[]>
  serviceControlPolicyErrors?: Record<string, ValidationError[]>
  resourceControlPolicyErrors?: Record<string, ValidationError[]>
  permissionBoundaryErrors?: Record<string, ValidationError[]>
  resourcePolicyErrors?: ValidationError[]
  vpcEndpointErrors?: Record<string, ValidationError[]>
  anonymousRequestErrors?: string[]
  message: string
}

/**
 * Result of evaluating a single resource simulation, containing the analysis and any ignored context keys.
 */
export interface SimulationResourceResult {
  analysis: RequestAnalysis

  /**
   * Any context keys provided in the request that were filtered out before
   * policy evaluation because they do not apply to the action/resource type.
   *
   * This will only be present if the request passes validation to reach the
   * policy evaluation stage.
   *
   * If no context keys were ignored, this will be present and an empty array.
   */
  ignoredContextKeys?: string[]

  /**
   * The resource type that was used for the simulation.
   */
  resourceType?: string | undefined
}

/**
 * Extended simulation resource result that includes resource type and pattern information
 * for wildcard resource simulations.
 */
export interface WildcardSimulationResourceResult extends SimulationResourceResult {
  /**
   * The resource type that was used for the simulation.
   */
  resourceType: string

  /**
   * The resource pattern that was used for the simulation, if applicable. If a wildcard
   * resource was provided and multiple simulations were run, this will indicate the
   * specific resource string that was simulated.
   */
  resourcePattern: string
}

/**
 * Simulation result indicating that errors prevented the simulation from running.
 */
export interface ErrorSimulationResult {
  resultType: 'error'

  /**
   * Errors in the simulation input that prevented the simulation from being run.
   */
  errors: SimulationErrors
}

/**
 * Simulation result for a single resource (non-wildcard) evaluation.
 */
export interface SingleResourceSimulationResult {
  /**
   * A single resource simulation result.
   */
  resultType: 'single'

  /**
   * The overall result of the one simulation that was run.
   */
  overallResult: EvaluationResult

  /**
   * The detailed result of the simulation that was run and the request analysis
   */
  result: SimulationResourceResult
}

/**
 * Simulation results for wildcard resource evaluations, containing multiple individual results.
 */
export interface WildcardResourceSimulationResults {
  /**
   * Whether a wildcard was detected in the resource ARN of the request and the
   * simulation was not a wildcard-only action, which can cause multiple simulations to be run.
   */
  resultType: 'wildcard'

  /**
   * The overall result of the simulation, calculated based on the results of individual simulations if
   * multiple were run.
   */
  overallResult: EvaluationResult

  /**
   * The results of the simulation or simulations that were run.
   * If it is a wildcard only action or the resource ARN contains no wildcards, this will contain a single result.
   * If the resource ARN contains a wildcard and the action is not a wildcard-only action, this may contain no
   * results, or one result for each matching pattern found in the provided identity and resource policies.
   */
  results: WildcardSimulationResourceResult[]
}

/**
 * The result of running a simulation.
 * Can be an error, a single result, or a wildcard result.
 * Discriminated by the `resultType` field.
 */
export type RunSimulationResults =
  ErrorSimulationResult | SingleResourceSimulationResult | WildcardResourceSimulationResults

/**
 * Union type representing successful simulation results (excluding error cases).
 */
export type SuccessfulRunSimulationResults =
  SingleResourceSimulationResult | WildcardResourceSimulationResults

/**
 * Discriminant type for the different kinds of simulation results.
 */
export type SimulationResultType = RunSimulationResults['resultType']

/**
 * Returns pre-computed validation errors from a ValidatedPolicy, or runs the
 * validation function against a raw policy document.
 *
 * @param policy a raw policy document or a ValidatedPolicy
 * @param validateFn the validation function to apply if the policy is not already validated
 * @returns the array of validation errors (empty if valid)
 */
function validateOrReuse(
  policy: any,
  validateFn: (policy: any) => ValidationError[]
): ValidationError[] {
  if (isValidatedPolicy(policy)) {
    return [...policy.errors]
  }
  return validateFn(policy)
}

/**
 * Finds principal-side policy inputs that are invalid for anonymous requests.
 *
 * @param simulation the simulation input to validate.
 * @returns anonymous request validation error message identifiers.
 */
function anonymousRequestValidationErrors(simulation: Simulation): string[] {
  const errors: string[] = []
  if (simulation.sessionPolicy) {
    errors.push('anonymous.sessionPolicy.invalid')
  }
  if (simulation.identityPolicies.length > 0) {
    errors.push('anonymous.identityPolicies.invalid')
  }
  if ((simulation.permissionBoundaryPolicies?.length ?? 0) > 0) {
    errors.push('anonymous.permissionBoundaryPolicies.invalid')
  }
  if (simulation.serviceControlPolicies.length > 0) {
    errors.push('anonymous.serviceControlPolicies.invalid')
  }
  return errors
}

/**
 * Run a simulation with validation
 *
 * @param simulation The simulation to run
 * @param simulationOptions Options for the simulation
 * @returns The results of the simulation, or errors if the simulation could not be run
 */
export async function runSimulation(
  simulation: Simulation,
  simulationOptions: Partial<SimulationOptions>
): Promise<RunSimulationResults> {
  const principal = simulation.request.principal
  const resourceArn = simulation.request.resource.resource
  const resourceHasWildcard = resourceArn.includes('*')

  if (!isSimulationRequestPrincipal(principal)) {
    return {
      resultType: 'error',
      errors: {
        message: 'invalid.principal'
      }
    }
  }

  if (isAnonymousRequestPrincipal(principal)) {
    const anonymousRequestErrors = anonymousRequestValidationErrors(simulation)
    if (anonymousRequestErrors.length > 0) {
      return {
        resultType: 'error',
        errors: {
          anonymousRequestErrors,
          message:
            anonymousRequestErrors.length === 1
              ? anonymousRequestErrors[0]
              : 'anonymous.policies.invalid'
        }
      }
    }
  }

  if (simulation.sessionPolicy) {
    if (
      typeof principal !== 'string' ||
      (!isIamRoleArn(principal) && !isAssumedRoleArn(principal) && !isFederatedUserArn(principal))
    ) {
      return {
        resultType: 'error',
        errors: {
          message: 'session.policy.invalid.principal'
        }
      }
    }
  }

  const sessionPolicyErrors = simulation.sessionPolicy
    ? validateOrReuse(simulation.sessionPolicy, validateIdentityPolicy)
    : []
  const sessionPolicy = simulation.sessionPolicy
    ? loadPolicy(simulation.sessionPolicy, { name: 'SessionPolicy' })
    : undefined

  const identityPolicyErrors: Record<string, ValidationError[]> = {}
  const identityPolicies: PolicyWithName[] = []
  simulation.identityPolicies.forEach((value) => {
    const { name, policy } = value
    const validationErrors = validateOrReuse(policy, validateIdentityPolicy)
    if (validationErrors.length == 0) {
      identityPolicies.push(loadPolicy(policy, { name }))
    } else {
      identityPolicyErrors[name] = validationErrors
    }
  })

  const serviceControlPolicyErrors: Record<string, ValidationError[]> = {}
  const serviceControlPolicies: ControlPolicies[] = simulation.serviceControlPolicies.map((scp) => {
    const ouId = scp.orgIdentifier
    const validPolicies: PolicyWithName[] = []

    scp.policies.forEach((value) => {
      const { name, policy } = value
      const validationErrors = validateOrReuse(policy, validateServiceControlPolicy)
      if (validationErrors.length > 0) {
        serviceControlPolicyErrors[name] = validationErrors
      } else {
        validPolicies.push(loadPolicy(policy, { name }))
      }
    })

    return {
      orgIdentifier: ouId,
      policies: validPolicies
    }
  })

  const resourceControlPolicyErrors: Record<string, ValidationError[]> = {}
  const resourceControlPolicies: ControlPolicies[] = simulation.resourceControlPolicies.map(
    (rcp) => {
      const ouId = rcp.orgIdentifier
      const validPolicies: PolicyWithName[] = []
      validPolicies.push(loadPolicy(DEFAULT_RCP.policy, { name: DEFAULT_RCP.arn }))

      rcp.policies.forEach((value) => {
        const { name, policy } = value
        const validationErrors = validateOrReuse(policy, validateResourceControlPolicy)
        if (validationErrors.length > 0) {
          resourceControlPolicyErrors[name] = validationErrors
        } else {
          validPolicies.push(loadPolicy(policy, { name }))
        }
      })

      return {
        orgIdentifier: ouId,
        policies: validPolicies
      }
    }
  )

  const resourcePolicyErrors = simulation.resourcePolicy
    ? validateOrReuse(simulation.resourcePolicy, validateResourcePolicy)
    : []

  const permissionBoundaries: PolicyWithName[] | undefined = simulation.permissionBoundaryPolicies
    ? []
    : undefined
  const permissionBoundaryErrors: Record<string, ValidationError[]> = {}
  simulation.permissionBoundaryPolicies?.map((pb) => {
    const { name, policy } = pb
    const validationErrors = validateOrReuse(policy, validateIdentityPolicy)
    if (validationErrors.length == 0) {
      permissionBoundaries!.push(loadPolicy(policy, { name }))
    } else {
      permissionBoundaryErrors[name] = validationErrors
    }
  })

  const vpcEndpointPolicies: PolicyWithName[] | undefined = simulation.vpcEndpointPolicies
    ? []
    : undefined
  const vpcEndpointErrors: Record<string, ValidationError[]> = {}
  simulation.vpcEndpointPolicies?.map((endpointPolicy) => {
    const { name, policy } = endpointPolicy
    const validationErrors = validateOrReuse(policy, validateEndpointPolicy)
    if (validationErrors.length == 0) {
      vpcEndpointPolicies!.push(loadPolicy(policy, { name }))
    } else {
      vpcEndpointErrors[name] = validationErrors
    }
  })

  if (
    Object.keys(identityPolicyErrors).length > 0 ||
    Object.keys(serviceControlPolicyErrors).length > 0 ||
    Object.keys(resourceControlPolicyErrors).length > 0 ||
    Object.keys(permissionBoundaryErrors).length > 0 ||
    Object.keys(vpcEndpointErrors).length > 0 ||
    resourcePolicyErrors.length > 0 ||
    sessionPolicyErrors.length > 0
  ) {
    return {
      resultType: 'error',
      errors: {
        ...(sessionPolicyErrors.length > 0 && { sessionPolicyErrors }),
        ...(Object.keys(identityPolicyErrors).length > 0 && { identityPolicyErrors }),
        ...(Object.keys(serviceControlPolicyErrors).length > 0 && { serviceControlPolicyErrors }),
        ...(Object.keys(resourceControlPolicyErrors).length > 0 && { resourceControlPolicyErrors }),
        ...(resourcePolicyErrors.length > 0 && { resourcePolicyErrors }),
        ...(Object.keys(permissionBoundaryErrors).length > 0 && { permissionBoundaryErrors }),
        ...(Object.keys(vpcEndpointErrors).length > 0 && { vpcEndpointErrors }),
        message: 'policy.errors'
      }
    }
  }

  const resourcePolicy = simulation.resourcePolicy
    ? loadPolicy<{ name: string }>(simulation.resourcePolicy, {
        name: simulation.resourcePolicy.name
      })
    : undefined

  if (simulation.request.action.split(':').length != 2) {
    return {
      resultType: 'error',
      errors: {
        message: 'invalid.action'
      }
    }
  }

  const [service, action] = simulation.request.action.split(':')
  const validService = await iamServiceExists(service)
  if (!validService) {
    return {
      resultType: 'error',
      errors: {
        message: 'invalid.service'
      }
    }
  }
  const validAction = await iamActionExists(service, action)
  if (!validAction) {
    return {
      resultType: 'error',
      errors: {
        message: 'invalid.action'
      }
    }
  }

  const isWildCardOnlyAction = await isWildcardOnlyAction(service, action)
  const runMultipleSimulations = resourceHasWildcard && !isWildCardOnlyAction
  let resourceTypes: ResourceType[] | undefined = undefined
  if (isWildCardOnlyAction) {
    if (resourceArn !== '*') {
      return {
        resultType: 'error',
        errors: {
          message: 'must.use.wildcard'
        }
      }
    }
  } else {
    const actionResourceTypes = await getResourceTypesForAction(service, action, resourceArn)
    if (actionResourceTypes.length === 0) {
      return {
        resultType: 'error',
        errors: {
          message: 'no.resource.types'
        }
      }
    } else if (actionResourceTypes.length > 1 && !resourceHasWildcard) {
      return {
        resultType: 'error',
        errors: {
          message: 'multiple.resource.types'
        }
      }
    } else {
      resourceTypes = actionResourceTypes.map((item) => item)
    }
  }

  const simulationMode = validSimulationModes.includes(
    simulationOptions.simulationMode as SimulationMode
  )
    ? (simulationOptions.simulationMode as SimulationMode)
    : 'Strict'

  // For each resource type, find the resource patterns, for each pattern, run a simulation

  const discoveryContextKeyConstraints =
    simulationMode === 'Discovery'
      ? new DiscoveryContextKeyConstraints(simulationOptions.discoveryContextKeyConstraints || [])
      : new DiscoveryContextKeyConstraints([])

  const curriedAuthorize = (
    curriedResourceString: string,
    curriedContextValues: Record<string, string | string[]>
  ) =>
    authorize({
      request: new AwsRequestImpl(
        principal,
        {
          resource: expandShortArn(curriedResourceString),
          accountId: simulation.request.resource.accountId
        },
        simulation.request.action,
        new RequestContextImpl(curriedContextValues),
        isWildCardOnlyAction
      ),
      sessionPolicy,
      identityPolicies,
      serviceControlPolicies,
      resourceControlPolicies,
      resourcePolicy,
      permissionBoundaries,
      vpcEndpointPolicies,
      simulationParameters: {
        simulationMode: simulationMode,
        discoveryContextKeyConstraints
      },
      serviceSettings: {
        s3: {
          blockPublicAccess: simulation.additionalSettings?.s3?.blockPublicAccess
        }
      }
    })

  const identityPoliciesThatGrantAccess: (PolicyWithName | undefined)[] = [...identityPolicies]
  const resourcePoliciesThatGrantAccess: (PolicyWithName | undefined)[] = [resourcePolicy]

  // If there is only one simulation to run, run it
  if (!runMultipleSimulations) {
    const { validContextValues, ignoredContextKeys } = await normalizeSimulationParameters(
      simulation,
      undefined
    )
    const singleResult = curriedAuthorize(resourceArn, validContextValues)
    return {
      resultType: 'single',
      overallResult: singleResult.result,
      result: {
        analysis: singleResult,
        ...(resourceTypes?.length === 1 ? { resourceType: resourceTypes![0].key } : {}),
        ignoredContextKeys
      }
    }
  }

  // Here, we know it is a wildcard resource and not a wildcard-only action, so we need to run multiple simulations
  const simulationResults: WildcardSimulationResourceResult[] = []
  const resourceTypesToSimulate: Array<ResourceType> =
    resourceTypes && resourceTypes.length > 0 ? resourceTypes : []
  for (const resourceType of resourceTypesToSimulate) {
    // If "run multiple" get the resource strings that match the wildcard pattern, otherwise, just run the one.

    const { validContextValues, ignoredContextKeys } = await normalizeSimulationParameters(
      simulation,
      resourceType
    )

    //Run the pattern directly first.
    const exactPatternResult = curriedAuthorize(resourceArn, validContextValues)
    if (exactPatternResult.result === 'ExplicitlyDenied') {
      simulationResults.push({
        analysis: exactPatternResult,
        ignoredContextKeys,
        resourceType: resourceType.key,
        resourcePattern: resourceArn
      })
    } else if (exactPatternResult.result !== 'ImplicitlyDenied') {
      // If the requested pattern is implicitly denied, narrower overlapping policy patterns cannot
      // make the overall request allowed because exact-pattern evaluation already considers any
      // overlapping identity, resource, and guardrail policy statements.
      const identityResourceStrings = getMatchingResourceStringsForPolicies(
        identityPoliciesThatGrantAccess,
        simulation.request.action,
        resourceType,
        simulation.request.resource.resource,
        true
      )
      const resourcePolicyResourceStrings = getMatchingResourceStringsForPolicies(
        resourcePoliciesThatGrantAccess,
        simulation.request.action,
        resourceType,
        simulation.request.resource.resource,
        false
      )
      const resourceStrings = [
        ...new Set([...identityResourceStrings, ...resourcePolicyResourceStrings])
      ]

      for (const resourceString of resourceStrings) {
        const simulationResult = curriedAuthorize(resourceString, validContextValues)
        const mergedConditions =
          simulationResult.result === 'Allowed'
            ? mergeAllowedConditionExpressions([
                simulationResult.conditions,
                exactPatternResult.conditions
              ])
            : undefined

        simulationResults.push({
          analysis: mergedConditions
            ? { ...simulationResult, conditions: mergedConditions }
            : simulationResult,
          ignoredContextKeys,
          resourceType: resourceType.key,
          resourcePattern: resourceString
        })
      }
    }
  }

  const overallResult = calculateOverallResult(simulationResults)
  return {
    resultType: 'wildcard',
    overallResult,
    results: simulationResults
  }
}

export async function normalizeSimulationParameters(
  simulation: Simulation,
  suggestedResourceType: ResourceType | undefined
): Promise<{
  validContextValues: Record<string, string | string[]>
  ignoredContextKeys: string[]
}> {
  const [service, action] = simulation.request.action.split(':')
  const resourceArn = simulation.request.resource.resource
  const contextVariablesForAction = new Set(
    await allowedContextKeysForRequest(
      service,
      action,
      resourceArn,
      !!simulation.additionalSettings?.s3?.bucketAbacEnabled,
      suggestedResourceType
    )
  )

  //Get the types of the context variables and set a string or array of strings based on that.
  const validContextValues: Record<string, string | string[]> = {}
  const ignoredContextKeys: string[] = []
  for (const key of Object.keys(simulation.request.contextVariables)) {
    const value = simulation.request.contextVariables[key]
    const lowerCaseKey = key.toLowerCase()
    if (
      contextVariablesForAction.has(lowerCaseKey) ||
      listHasVariableKeyMatch(lowerCaseKey, contextVariablesForAction)
    ) {
      const conditionType = await typeForContextKey(lowerCaseKey)
      const normalizedKey = await normalizeContextKeyCase(key)

      if (isConditionKeyArray(conditionType)) {
        validContextValues[normalizedKey] = [value].flat()
      } else if (Array.isArray(value)) {
        validContextValues[normalizedKey] = value[0]
      } else {
        validContextValues[normalizedKey] = value
      }
    } else {
      ignoredContextKeys.push(key)
    }
  }

  return {
    validContextValues,
    ignoredContextKeys
  }
}

/**
 * Evaluates a context key with a variable such as `aws:PrincipalTag/Foo` to see
 * if it matches any of the context variables in the allowed variables set.
 *
 * @param lowerCaseKey The lower case key to check for a match.
 * @param contextVariables The set of context variables to check against.
 * @returns True if the key has a variable match, false otherwise.
 */
function listHasVariableKeyMatch(lowerCaseKey: string, contextVariables: Set<string>): boolean {
  const firstSlashIndex = lowerCaseKey.indexOf('/')
  if (firstSlashIndex === -1) {
    return false
  }

  const prefix = lowerCaseKey.slice(0, firstSlashIndex + 1)
  for (const variable of contextVariables) {
    if (variable.startsWith(prefix)) {
      return true
    }
  }

  return false
}
