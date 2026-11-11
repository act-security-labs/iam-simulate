import { isCloudFrontOriginAccessUserArn } from '@actsecurity/iam-utils'
import {
  isAnonymousRequestPrincipal,
  isSimulationRequestPrincipal,
  type SimulationRequestPrincipal
} from '../simulation_engine/simulation.js'

export type RequestPrincipalKind = 'Authenticated' | 'Anonymous'

/**
 * Common request-principal behavior shared by anonymous and authenticated requests.
 */
export interface RequestPrincipal {
  /**
   * The kind of request principal being simulated.
   *
   * @returns the request principal kind.
   */
  kind(): RequestPrincipalKind

  /**
   * Whether the request principal represents an unsigned anonymous request.
   *
   * @returns true if this is an anonymous request principal.
   */
  isAnonymous(): this is AnonymousRequestPrincipal

  /**
   * Whether the request principal is an authenticated principal request
   */
  isAuthenticated(): this is AuthenticatedRequestPrincipal
}

/**
 * An unsigned anonymous request principal.
 */
export interface AnonymousRequestPrincipal extends RequestPrincipal {
  kind(): 'Anonymous'
}

/**
 * An authenticated request principal represented by a concrete principal string.
 */
export interface AuthenticatedRequestPrincipal extends RequestPrincipal {
  kind(): 'Authenticated'

  /**
   * The raw string of the authenticated principal.
   *
   * @returns the principal string.
   */
  value(): string

  /**
   * The account id of the principal, if the principal is an ARN that has an account ID, otherwise undefined.
   *
   * @returns the principal account ID, if available.
   */
  accountId(): string | undefined
}

/**
 * Checks whether a request principal is authenticated.
 *
 * @param principal the request principal to check.
 * @returns true if the principal is authenticated and can expose an account ID and value.
 */
/**
 * Asserts that a request principal is authenticated.
 *
 * @param principal the request principal to assert.
 */
export function assertAuthenticatedRequestPrincipal(
  principal: RequestPrincipal
): asserts principal is AuthenticatedRequestPrincipal {
  if (principal.isAuthenticated()) {
    return
  }
  throw new Error('invalid.principal')
}

/**
 * Creates a request-principal implementation from public simulation input.
 *
 * @param input the principal input from a simulation request.
 * @returns a request-principal implementation for the input.
 */
export function requestPrincipalFromInput(input: SimulationRequestPrincipal): RequestPrincipal {
  if (!isSimulationRequestPrincipal(input)) {
    throw new Error('invalid.principal')
  }
  if (isAnonymousRequestPrincipal(input)) {
    return new AnonymousRequestPrincipalImpl()
  }
  return new AuthenticatedRequestPrincipalImpl(input)
}

/**
 * A string-valued authenticated request principal.
 */
export class AuthenticatedRequestPrincipalImpl implements AuthenticatedRequestPrincipal {
  /**
   * Create an authenticated request principal.
   *
   * @param rawValue the raw principal string.
   */
  constructor(private readonly rawValue: string) {}

  kind(): 'Authenticated' {
    return 'Authenticated'
  }

  isAnonymous(): this is AnonymousRequestPrincipal {
    return false
  }

  isAuthenticated(): this is AuthenticatedRequestPrincipal {
    return true
  }

  public value(): string {
    return this.rawValue
  }

  accountId(): string | undefined {
    if (isCloudFrontOriginAccessUserArn(this.value())) {
      return undefined
    }
    const arnParts = this.value().split(':')
    if (arnParts.length < 6 || arnParts[0] !== 'arn') {
      return undefined
    }
    return arnParts[4] || undefined
  }

  //TODO: A principal is a Service Linked Role if it is an ARN and has the path arn:aws:iam::111111111111:role/aws-service-role/...
}

/**
 * An unsigned anonymous request principal.
 */
export class AnonymousRequestPrincipalImpl implements AnonymousRequestPrincipal {
  kind(): 'Anonymous' {
    return 'Anonymous'
  }

  isAnonymous(): this is AnonymousRequestPrincipal {
    return true
  }

  isAuthenticated(): this is AuthenticatedRequestPrincipal {
    return false
  }
}
