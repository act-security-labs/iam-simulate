import { normalizeCaseInsensitive } from '@actsecurity/iam-utils'

/** Shared key or pattern field for Discovery context-key constraints. */
interface DiscoveryContextKeyConstraintKey {
  /**
   * Context key name or slash-delimited regular expression pattern.
   *
   * Literal names are matched case-insensitively. Regex-style names such as
   * a ResourceTag-prefix pattern are also matched case-insensitively.
   */
  keyName: string
}

/**
 * Discovery knowledge for a key whose presence and concrete value are both known.
 */
interface KnownPresenceKnownValueConstraint {
  /** Presence/absence in the request context is authoritative. */
  presenceIsKnown: true

  /** The concrete value in the request context is authoritative when the key is present. */
  valueIsKnown: true
}

/**
 * Discovery knowledge for a key whose presence is known but concrete value is not.
 */
interface KnownPresenceUnknownValueConstraint {
  /** Presence/absence in the request context is authoritative. */
  presenceIsKnown: true

  /** The concrete value in the request context is not authoritative. */
  valueIsKnown: false
}

/**
 * Discovery knowledge for a key whose presence is unknown.
 *
 * Value knowledge must also be unknown because a value cannot be authoritative
 * when the key might not exist.
 */
interface UnknownPresenceConstraint {
  /** Presence/absence in the request context is not authoritative. */
  presenceIsKnown: false

  /** Must be false because value knowledge requires known presence. */
  valueIsKnown: false
}

/**
 * Caller-provided Discovery-mode knowledge about a single context key or key pattern.
 *
 * These constraints do not add context keys to the request. The request context
 * still determines whether a key is actually present. A constraint only tells
 * Discovery mode whether it can trust that presence and/or the concrete value.
 *
 * The discriminated union intentionally makes `{ presenceIsKnown: false,
 * valueIsKnown: true }` unrepresentable in TypeScript.
 */
export type DiscoveryContextKeyConstraint = DiscoveryContextKeyConstraintKey &
  (
    | KnownPresenceKnownValueConstraint
    | KnownPresenceUnknownValueConstraint
    | UnknownPresenceConstraint
  )

/**
 * Resolved Discovery-mode knowledge for a specific context key lookup.
 *
 * This is the effective result after merging all matching literal, prefix, and
 * regex constraints. If no constraint matches, both booleans are false and
 * `explicitlyConfigured` is false, which tells condition evaluation to preserve
 * the current unconstrained Discovery behavior for that key.
 *
 * The discriminated union intentionally makes `{ presenceIsKnown: false,
 * valueIsKnown: true }` unrepresentable in TypeScript.
 */
export type EffectiveDiscoveryContextKeyConstraint = (
  | KnownPresenceKnownValueConstraint
  | KnownPresenceUnknownValueConstraint
  | UnknownPresenceConstraint
) & {
  /** Whether at least one caller-provided constraint matched the looked-up key. */
  explicitlyConfigured: boolean
}

const unconstrained: EffectiveDiscoveryContextKeyConstraint = {
  presenceIsKnown: false,
  valueIsKnown: false,
  explicitlyConfigured: false
}

const knownAbsent: EffectiveDiscoveryContextKeyConstraint = {
  presenceIsKnown: true,
  valueIsKnown: true,
  explicitlyConfigured: true
}

/**
 * Internal representation of the two knowledge booleans stored in lookup indexes.
 *
 * This intentionally omits `explicitlyConfigured` because any value in an index
 * is, by definition, from a caller-provided constraint. The same union is used
 * internally so the invalid `presenceIsKnown: false, valueIsKnown: true` state
 * remains unrepresentable after indexing and merging.
 */
type StoredConstraint =
  | KnownPresenceKnownValueConstraint
  | KnownPresenceUnknownValueConstraint
  | UnknownPresenceConstraint

/**
 * Internal optimized representation for regex constraints that are reducible to
 * simple lower-case prefix checks, such as a ResourceTag-prefix pattern.
 */
type PrefixConstraint = StoredConstraint & {
  /** Lower-case prefix that must start the looked-up context key. */
  prefixLower: string
}

/**
 * Internal fallback representation for complex regex constraints that cannot be
 * reduced to a simple prefix check.
 */
type RegexConstraint = StoredConstraint & {
  /** Compiled case-insensitive pattern to test against context key names. */
  pattern: RegExp
}

/**
 * Discovery-only context key knowledge constraints.
 *
 * The request context still determines whether a key is present. These constraints
 * describe whether Discovery mode can trust that presence and/or concrete value.
 */
export class DiscoveryContextKeyConstraints {
  private literalConstraints: Map<string, StoredConstraint> = new Map()
  private prefixConstraintsByService: Map<string, PrefixConstraint[]> = new Map()
  private regexConstraints: RegexConstraint[] = []
  private resolvedCache: Map<string, EffectiveDiscoveryContextKeyConstraint> = new Map()

  /**
   * Create Discovery context key constraints.
   *
   * @param constraints the constraint definitions to index
   * @param isUnsupportedContextKey whether a key cannot be carried by this request
   */
  constructor(
    constraints: DiscoveryContextKeyConstraint[] = [],
    private readonly isUnsupportedContextKey: (key: string) => boolean = () => false
  ) {
    for (const constraint of constraints) {
      const runtimeConstraint = constraint as {
        keyName: string
        presenceIsKnown: boolean
        valueIsKnown: boolean
      }
      if (!runtimeConstraint.presenceIsKnown && runtimeConstraint.valueIsKnown) {
        throw new Error(
          `Invalid discovery context key constraint for ${runtimeConstraint.keyName}: valueIsKnown requires presenceIsKnown`
        )
      }
      this.addConstraint(constraint)
    }
  }

  /**
   * Get the effective Discovery constraint for a context key.
   *
   * @param key the context key to look up
   * @returns the merged matching constraint, or an unconstrained result
   */
  public constraintFor(key: string): EffectiveDiscoveryContextKeyConstraint {
    const lowerKey = key.toLowerCase()
    // Regex matching can distinguish names that normalizeCaseInsensitive equates.
    const cached = this.resolvedCache.get(key)
    if (cached) {
      return cached
    }

    let result: EffectiveDiscoveryContextKeyConstraint = { ...unconstrained }
    const merge = (constraint: StoredConstraint) => {
      result = effectiveConstraint(
        result.presenceIsKnown || constraint.presenceIsKnown,
        result.valueIsKnown || constraint.valueIsKnown,
        true
      )
    }

    const literal = this.literalConstraints.get(normalizeCaseInsensitive(key))
    if (literal) {
      merge(literal)
    }

    const service = lowerKey.split(':')[0]
    const prefixConstraints = this.prefixConstraintsByService.get(service) ?? []
    for (const constraint of prefixConstraints) {
      if (lowerKey.startsWith(constraint.prefixLower)) {
        merge(constraint)
      }
    }

    for (const constraint of this.regexConstraints) {
      if (constraint.pattern.test(key)) {
        merge(constraint)
      }
    }

    if (!result.explicitlyConfigured && this.isUnsupportedContextKey(key)) {
      result = knownAbsent
    }
    this.resolvedCache.set(key, result)
    return result
  }

  /**
   * Adds a caller-provided constraint to the appropriate lookup index.
   *
   * Literal keys are stored in a case-insensitive map. Simple prefix-like regex
   * patterns are stored in prefix buckets, and complex regex patterns fall back
   * to the regex list.
   *
   * @param constraint the caller-provided constraint to index
   */
  private addConstraint(constraint: DiscoveryContextKeyConstraint) {
    const stored = storedConstraint(constraint.presenceIsKnown, constraint.valueIsKnown)

    if (constraint.keyName.startsWith('/') && constraint.keyName.endsWith('/')) {
      const patternText = constraint.keyName.slice(1, -1)
      const prefix = regexPrefix(patternText)
      if (prefix) {
        const service = prefix.split(':')[0]
        const constraints = this.prefixConstraintsByService.get(service) ?? []
        constraints.push({ ...stored, prefixLower: prefix })
        this.prefixConstraintsByService.set(service, constraints)
      } else {
        this.regexConstraints.push({ ...stored, pattern: new RegExp(patternText, 'i') })
      }
    } else {
      const key = normalizeCaseInsensitive(constraint.keyName)
      const existing = this.literalConstraints.get(key)
      this.literalConstraints.set(key, existing ? mergeStored(existing, stored) : stored)
    }
  }
}

/**
 * Merges two stored constraints with true-winning OR semantics.
 *
 * @param a the first stored constraint
 * @param b the second stored constraint
 * @returns the merged constraint
 */
function mergeStored(a: StoredConstraint, b: StoredConstraint): StoredConstraint {
  return storedConstraint(a.presenceIsKnown || b.presenceIsKnown, a.valueIsKnown || b.valueIsKnown)
}

/**
 * Builds a stored constraint while preserving the valid-state union.
 *
 * @param presenceIsKnown whether presence/absence is authoritative
 * @param valueIsKnown whether the concrete value is authoritative
 * @returns a stored constraint in one of the valid knowledge states
 */
function storedConstraint(presenceIsKnown: boolean, valueIsKnown: boolean): StoredConstraint {
  if (valueIsKnown) {
    return { presenceIsKnown: true, valueIsKnown: true }
  }
  return presenceIsKnown
    ? { presenceIsKnown: true, valueIsKnown: false }
    : { presenceIsKnown: false, valueIsKnown: false }
}

/**
 * Builds an effective constraint while preserving the valid-state union.
 *
 * @param presenceIsKnown whether presence/absence is authoritative
 * @param valueIsKnown whether the concrete value is authoritative
 * @param explicitlyConfigured whether any configured constraint matched
 * @returns an effective constraint in one of the valid knowledge states
 */
function effectiveConstraint(
  presenceIsKnown: boolean,
  valueIsKnown: boolean,
  explicitlyConfigured: boolean
): EffectiveDiscoveryContextKeyConstraint {
  return { ...storedConstraint(presenceIsKnown, valueIsKnown), explicitlyConfigured }
}

/**
 * Extracts a lower-case literal prefix from simple anchored regex patterns.
 *
 * Only simple patterns such as `^aws:ResourceTag/.*` are converted. More
 * complex patterns return undefined and are evaluated with RegExp directly.
 *
 * @param patternText the regex source without surrounding slashes
 * @returns a lower-case prefix if the pattern is reducible to startsWith
 */
function regexPrefix(patternText: string): string | undefined {
  const match = patternText.match(/^\^([A-Za-z0-9:_/-]+)(?:\.\*|\.\*\?)?\/?$/)
  if (!match) {
    return undefined
  }
  return match[1].toLowerCase()
}
