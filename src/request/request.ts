import { type ContextKey, type RequestContext } from '../requestContext.js'
import { type SimulationRequestPrincipal } from '../simulation_engine/simulation.js'
import { type RequestAction, RequestActionImpl } from './requestAction.js'
import { requestPrincipalFromInput, type RequestPrincipal } from './requestPrincipal.js'
import { type RequestResource, ResourceRequestImpl } from './requestResource.js'

/**
 * A request to be evaluated by the policy engine
 */
export interface AwsRequest {
  principal: RequestPrincipal

  /**
   * The action to be performed
   */
  action: RequestAction

  /**
   * The resource to be acted upon
   */
  resource: RequestResource

  /**
   * Whether the action is a wildcard-only action, meaning it does not support
   * resource-level permissions and must use "*" as the resource. When true,
   * only a literal "*" policy resource will match a "*" request resource;
   * specific ARNs in the policy will not match.
   */
  wildcardOnlyAction: boolean

  /**
   * Whether AWS rejects unsigned requests for the action regardless of resource policy.
   */
  actionBlockedForAnonymous: boolean

  /**
   * The context of the request
   */
  context: RequestContext

  /**
   * Checks to see if a context key is valid for the request and
   * exists in the context
   *
   * @param key the key to check for existence
   * @returns true if the key is valid for the request and exists in the request context.
   */
  contextKeyExists(key: string): boolean

  /**
   * Gets the value of a context key, if it is valid for the request and exist, otherwise throws an error
   * @param key the key to get the value of
   *
   * @returns the value of the context key
   */
  getContextKeyValue(key: string): ContextKey
}

/**
 * Concrete immutable request used by the synchronous policy authorization engine.
 *
 * @param principalInput the principal initiating the request.
 * @param resourceIdentifier the resource ARN and account context for the request.
 * @param actionString the IAM action being requested.
 * @param context the request context available to policy conditions.
 * @param wildcardOnlyAction whether the action only permits the wildcard resource.
 * @param actionBlockedForAnonymous whether AWS rejects unsigned requests for the action.
 */
export class AwsRequestImpl implements AwsRequest {
  public readonly wildcardOnlyAction: boolean
  public readonly actionBlockedForAnonymous: boolean
  private readonly requestPrincipal: RequestPrincipal

  constructor(
    public readonly principalInput: SimulationRequestPrincipal,
    public readonly resourceIdentifier: { resource: string; accountId: string },
    public readonly actionString: string,
    public readonly context: RequestContext,
    wildcardOnlyAction?: boolean,
    actionBlockedForAnonymous?: boolean
  ) {
    this.wildcardOnlyAction = wildcardOnlyAction ?? false
    this.actionBlockedForAnonymous = actionBlockedForAnonymous ?? false
    this.requestPrincipal = requestPrincipalFromInput(this.principalInput)
  }

  get action(): RequestAction {
    return new RequestActionImpl(this.actionString)
  }

  get resource(): RequestResource {
    return new ResourceRequestImpl(
      this.resourceIdentifier.resource,
      this.resourceIdentifier.accountId
    )
  }

  get principal(): RequestPrincipal {
    return this.requestPrincipal
  }

  public contextKeyExists(key: string): boolean {
    return this.context.contextKeyExists(key)
  }

  public getContextKeyValue(key: string): ContextKey {
    if (!this.contextKeyExists(key)) {
      throw new Error(`Invalid context key: ${key}`)
    }
    return this.context.contextKeyValue(key)
  }
}
