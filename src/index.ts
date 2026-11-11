export {
  getDenialReasons,
  getGrantReasons,
  type DenialPolicyType,
  type RequestGrant,
  type RequestDenial
} from './analysis/analyzeResults.js'
export {
  iamStringEquals,
  iamStringEqualsIgnoreCase,
  iamStringEqualsNormalizeCaseInsensitive
} from './condition/string/ignoreCaseEquals.js'
export { typeForContextKey } from './context_keys/contextKeys.js'
export {
  isConditionKeyArray,
  type BaseConditionKeyType,
  type ConditionKeyType
} from './context_keys/contextKeyTypes.js'
export type { DiscoveryContextKeyConstraint } from './context_keys/discoveryContextKeyConstraints.js'
export { findContextKeys } from './context_keys/findContextKeys.js'
export type { SimulationMode } from './core_engine/CoreSimulatorEngine.js'
export type {
  AllowedConditionExpression,
  AllowedConditionGroup,
  AllowedConditionLeaf,
  AllowedConditionSource,
  AllowedSessionNameCondition,
  AlwaysAllowedCondition,
  BlockedReason,
  EvaluationResult,
  IgnoredCondition,
  IgnoredConditions,
  IdentityEvaluationResult,
  NeverAllowedCondition,
  RequestAnalysis
} from './evaluate.js'
export type {
  ActionExplain,
  ConditionExplain,
  ConditionValueExplain,
  ExplainPrincipalMatch,
  PrincipalExplain,
  ResourceExplain,
  StatementExplain
} from './explain/statementExplain.js'
export { allowedContextKeysForRequest } from './simulation_engine/contextKeys.js'
export {
  anonymousPrincipal,
  isAnonymousRequestPrincipal,
  isCloudFrontOriginAccessIdentityRequestPrincipal,
  isSimulationRequestPrincipal,
  type AnonymousRequestPrincipal,
  type CloudFrontOriginAccessIdentityRequestPrincipal,
  type Simulation,
  type SimulationIdentityPolicy,
  type SimulationOrgPolicies,
  type SimulationRequestPrincipal
} from './simulation_engine/simulation.js'
export { runSimulation } from './simulation_engine/simulationEngine.js'
export type {
  ErrorSimulationResult,
  RunSimulationResults,
  SimulationErrors,
  SimulationResourceResult,
  SimulationResultType,
  SingleResourceSimulationResult,
  SuccessfulRunSimulationResults,
  WildcardResourceSimulationResults,
  WildcardSimulationResourceResult
} from './simulation_engine/simulationEngine.js'
export type { SimulationOptions } from './simulation_engine/simulationOptions.js'
export { runUnsafeSimulation } from './simulation_engine/unsafeSimulationEngine.js'
export { isWildcardOnlyAction } from './util.js'
