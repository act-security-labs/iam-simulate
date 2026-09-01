import { type Principal, type Statement } from '@actsecurity/iam-policy'
import {
  convertAssumedRoleArnToRoleArn,
  isAssumedRoleArn,
  isFederatedUserArn,
  isIamRoleArn,
  splitArnParts
} from '@actsecurity/iam-utils'
import { type SimulationParameters } from '../core_engine/CoreSimulatorEngine.js'
import { type PrincipalExplain, type StatementExplain } from '../explain/statementExplain.js'
import { type AwsRequest } from '../request/request.js'
import { assertAuthenticatedRequestPrincipal } from '../request/requestPrincipal.js'

interface PrincipalAnalysis {
  explain: PrincipalExplain
  ignoredRoleSessionName?: boolean
}

//Wildcards are not allowed in the principal element https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html
// The only exception is the "*" wildcard, which you can use to match all principals, including anonymous principals.

/*
OIDC Session Principals:
Check federated and see if the string matches
SAML Session Principals:
Check the Federated string and see if it matches

IAM Identity Center principals // Ignore this for now.
*/

export type PrincipalMatchResult =
  'Match' | 'NoMatch' | 'AccountLevelMatch' | 'SessionRoleMatch' | 'SessionUserMatch'

/**
 * Check to see if a request matches a Principal element in an IAM policy statement
 *
 * @param request the request to check
 * @param principal the list of principals in the Principal element of the Statement
 * @returns if the request matches the Principal element, and if so, how it matches
 */
export function requestMatchesPrincipal(
  request: AwsRequest,
  principal: Principal[],
  simulationParameters: SimulationParameters,
  allowOrDeny: 'Allow' | 'Deny'
): {
  matches: PrincipalMatchResult
  explains: PrincipalExplain[]
  ignoredRoleSessionName?: boolean
} {
  const analyses = principal.map((principalStatement) =>
    requestMatchesPrincipalStatement(request, principalStatement, simulationParameters, allowOrDeny)
  )

  const explains = analyses.map((a) => a.explain)
  const anyIgnore = analyses.some((any) => any.ignoredRoleSessionName)
  const ignoredRoleSessionName = anyIgnore ? true : undefined

  // First check if any principal match without ignoring the role session name
  if (analyses.some((anys) => anys.explain.matches === 'Match' && !anys.ignoredRoleSessionName)) {
    return {
      matches: 'Match',
      explains,
      ignoredRoleSessionName
    }
  }

  if (explains.some((exp) => exp.matches === 'SessionUserMatch')) {
    return {
      matches: 'SessionUserMatch',
      explains,
      ignoredRoleSessionName
    }
  }

  if (explains.some((exp) => exp.matches === 'SessionRoleMatch')) {
    return {
      matches: 'SessionRoleMatch',
      explains,
      ignoredRoleSessionName
    }
  }

  // If there was a match, in Discovery mode, return a match and check for ignoredRoleSessionName
  if (
    simulationParameters.simulationMode === 'Discovery' &&
    analyses.some((any) => any.explain.matches === 'Match')
  ) {
    // The session role name could have been ignored in any statement

    return {
      matches: 'Match',
      explains,
      ignoredRoleSessionName
    }
  }

  if (explains.some((exp) => exp.matches === 'AccountLevelMatch')) {
    return {
      matches: 'AccountLevelMatch',
      explains,
      ignoredRoleSessionName
    }
  }

  return {
    matches: 'NoMatch',
    explains,
    ignoredRoleSessionName
  }
}

/**
 * Check to see if a request matches a NotPrincipal element in an IAM policy statement
 *
 * @param request the request to check
 * @param notPrincipal the list of principals in the NotPrincipal element of the Statement
 * @returns
 */
export function requestMatchesNotPrincipal(
  request: AwsRequest,
  notPrincipal: Principal[],
  simulationParameters: SimulationParameters,
  allowOrDeny: 'Allow' | 'Deny'
): { matches: PrincipalMatchResult; explains: PrincipalExplain[] } {
  // const matches = notPrincipal.map(principalStatement => requestMatchesPrincipalStatement(request, principalStatement))
  const analyses = notPrincipal.map((principalStatement) => {
    const analysis = requestMatchesPrincipalStatement(
      request,
      principalStatement,
      simulationParameters,
      allowOrDeny
    )
    /**
     * Need to do research on this. If there is an account level match on a NotPrincipal, does that
     * mean it tentatively matches the NotPrincipal, or does it mean it does not match the NotPrincipal?
     *
     * We need to test this.
     */

    // Invert the match result for NotPrincipal
    if (
      analysis.explain.matches === 'Match' ||
      analysis.explain.matches === 'AccountLevelMatch' ||
      analysis.explain.matches === 'SessionRoleMatch' ||
      analysis.explain.matches === 'SessionUserMatch'
    ) {
      analysis.explain.matches = 'NoMatch'
    } else {
      analysis.explain.matches = 'Match'
    }
    return analysis
  })

  if (analyses.some((exp) => exp.explain.matches === 'NoMatch')) {
    return {
      matches: 'NoMatch',
      explains: analyses.map((a) => a.explain)
    }
  }

  return {
    matches: 'Match',
    explains: analyses.map((a) => a.explain)
  }
}

/**
 * Check to see if a request matches a principal statement
 *
 * @param request the request to check
 * @param principalStatement the principal statement to check the request against
 * @returns if the request matches the principal statement, and if so, how it matches
 */
export function requestMatchesPrincipalStatement(
  request: AwsRequest,
  principalStatement: Principal,
  simulationParameters: SimulationParameters,
  allowOrDeny: 'Allow' | 'Deny'
): PrincipalAnalysis {
  const requestPrincipal = request.principal
  if (requestPrincipal.isAnonymous()) {
    return {
      explain: {
        matches: principalStatement.isWildcardPrincipal() ? 'Match' : 'NoMatch',
        principal: principalStatement.value()
      }
    }
  }
  assertAuthenticatedRequestPrincipal(requestPrincipal)

  if (principalStatement.isServicePrincipal()) {
    if (principalStatement.service() === requestPrincipal.value()) {
      return {
        explain: {
          matches: 'Match',
          principal: principalStatement.value()
        }
      }
    }
    return {
      explain: {
        matches: 'NoMatch',
        principal: principalStatement.value()
      }
    }
  }

  if (principalStatement.isCanonicalUserPrincipal()) {
    if (principalStatement.canonicalUser() === requestPrincipal.value()) {
      return {
        explain: {
          matches: 'Match',
          principal: principalStatement.value()
        }
      }
    }
    return {
      explain: {
        matches: 'NoMatch',
        principal: principalStatement.value()
      }
    }
  }

  if (principalStatement.isFederatedPrincipal()) {
    if (principalStatement.federated() === requestPrincipal.value()) {
      return {
        explain: {
          matches: 'Match',
          principal: principalStatement.value()
        }
      }
    }
    return {
      explain: {
        matches: 'NoMatch',
        principal: principalStatement.value()
      }
    }
  }

  if (principalStatement.isWildcardPrincipal()) {
    return {
      explain: {
        matches: 'Match',
        principal: principalStatement.value()
      }
    }
  }

  if (principalStatement.isAccountPrincipal()) {
    if (principalStatement.accountId() === requestPrincipal.accountId()) {
      return {
        explain: {
          matches: 'AccountLevelMatch',
          principal: principalStatement.value()
        }
      }
    }
    return {
      explain: {
        matches: 'NoMatch',
        principal: principalStatement.value()
      }
    }
  }

  if (principalStatement.isAwsPrincipal()) {
    if (isAssumedRoleArn(requestPrincipal.value())) {
      const sessionArn = requestPrincipal.value()
      if (roleArnMatchesAssumedRoleSession(principalStatement.arn(), sessionArn)) {
        return {
          explain: {
            matches: 'SessionRoleMatch',
            principal: principalStatement.value(),
            roleForSessionArn: principalStatement.arn()
          }
        }
      }
    } else if (isFederatedUserArn(requestPrincipal.value())) {
      const sessionArn = requestPrincipal.value()
      const userArn = userArnFromFederatedUserArn(sessionArn)
      if (principalStatement.arn() === userArn) {
        return {
          explain: {
            matches: 'SessionUserMatch',
            principal: principalStatement.value(),
            userForSessionArn: userArn
          }
        }
      }
    }

    if (principalStatement.arn() === requestPrincipal.value()) {
      return {
        explain: {
          matches: 'Match',
          principal: principalStatement.value()
        }
      }
    }

    /*
      If:
        - The simulation mode is Discovery
        - The principal in the statement is an assumed role ARN
        - The principal in the request is a Role or assumed role ARN
        - The base role ARN of the principal in the request matches the base role ARN in the statement
      Then:
        - Return a Match for the principal if Allow, or NoMatch if Deny
        - Indicate that the role session name was ignored for evaluation purposes
    */
    if (
      simulationParameters.simulationMode === 'Discovery' &&
      isAssumedRoleArn(principalStatement.arn())
    ) {
      const requestRoleArn = requestPrincipal.value()
      let roleMatchesSession = false
      if (isIamRoleArn(requestRoleArn)) {
        roleMatchesSession = roleArnMatchesAssumedRoleSession(
          requestRoleArn,
          principalStatement.arn()
        )
      } else if (isAssumedRoleArn(requestRoleArn)) {
        const principalRoleArn = convertAssumedRoleArnToRoleArn(principalStatement.arn())
        roleMatchesSession = principalRoleArn === convertAssumedRoleArnToRoleArn(requestRoleArn)
      }

      if (roleMatchesSession) {
        const discoveryMatch = allowOrDeny === 'Allow' ? 'Match' : 'NoMatch'
        return {
          explain: {
            matches: discoveryMatch,
            principal: principalStatement.value()
          },
          ignoredRoleSessionName: true // This is a role session match with the session name ignored
        }
      }
    }
  }

  return {
    explain: {
      matches: 'NoMatch',
      principal: principalStatement.value()
    }
  }
}

/**
 * Get a user ARN from a federated user ARN
 *
 * @param federatedUserArn the federated user ARN
 * @returns the user ARN for the federated user ARN
 */
export function userArnFromFederatedUserArn(federatedUserArn: string): string {
  const stsParts = federatedUserArn.split(':')
  const resource = stsParts.at(-1)!
  const username = resource.slice(resource.indexOf('/') + 1)
  return `arn:${stsParts[1]}:iam::${stsParts[4]}:user/${username}`
}

/**
 * Get the final segment from a slash-delimited path.
 *
 * @param path the slash-delimited path to inspect
 * @returns the final path segment, or undefined if the path is undefined or empty
 */
function lastPathSegment(path: string | undefined): string | undefined {
  if (!path) {
    return undefined
  }

  const lastSlashIndex = path.lastIndexOf('/')
  if (lastSlashIndex === -1) {
    return path
  }
  return path.slice(lastSlashIndex + 1)
}

/**
 * Get the first segment from a slash-delimited path.
 *
 * @param path the slash-delimited path to inspect
 * @returns the first path segment, or undefined if the path is undefined, empty, or has no slash
 */
function firstPathSegment(path: string | undefined): string | undefined {
  if (!path) {
    return undefined
  }

  const firstSlashIndex = path.indexOf('/')
  if (firstSlashIndex === -1) {
    return undefined
  }
  return path.slice(0, firstSlashIndex)
}

/**
 * Check whether an IAM role ARN represents the role for an assumed-role session ARN.
 *
 * @param roleArn the IAM role ARN to compare
 * @param sessionArn the assumed-role session ARN to compare
 * @returns true if the role ARN and session ARN have the same partition, account, and role name
 */
function roleArnMatchesAssumedRoleSession(roleArn: string, sessionArn: string): boolean {
  if (!isIamRoleArn(roleArn) || !isAssumedRoleArn(sessionArn)) {
    return false
  }

  const roleArnParts = splitArnParts(roleArn)
  const sessionArnParts = splitArnParts(sessionArn)
  if (
    roleArnParts.partition !== sessionArnParts.partition ||
    roleArnParts.accountId !== sessionArnParts.accountId
  ) {
    return false
  }

  const roleName = lastPathSegment(roleArnParts.resourcePath)
  const sessionRoleName = firstPathSegment(sessionArnParts.resourcePath)
  if (!roleName || !sessionRoleName) {
    return false
  }

  return roleName.localeCompare(sessionRoleName, 'en', { sensitivity: 'base' }) === 0
}

/**
 * Check if a request matches the Resource or NotResource elements of a statement.
 *
 * @param request the request to check
 * @param statement the statement to check against
 * @returns true if the request matches the resources in the statement, false otherwise
 */
export function requestMatchesStatementPrincipals(
  request: AwsRequest,
  statement: Statement,
  simulationParameters: SimulationParameters
): {
  matches: PrincipalMatchResult
  details: Pick<StatementExplain, 'principals' | 'notPrincipals' | 'noPrincipalElement'>
  ignoredRoleSessionName?: boolean
} {
  if (statement.isPrincipalStatement()) {
    const { matches, explains, ignoredRoleSessionName } = requestMatchesPrincipal(
      request,
      statement.principals(),
      simulationParameters,
      statement.effect() as 'Allow' | 'Deny'
    )
    return { matches, details: { principals: explains }, ignoredRoleSessionName }
  } else if (statement.isNotPrincipalStatement()) {
    const { matches, explains } = requestMatchesNotPrincipal(
      request,
      statement.notPrincipals(),
      simulationParameters,
      statement.effect() as 'Allow' | 'Deny'
    )
    return { matches, details: { notPrincipals: explains } }
  }
  return { matches: 'NoMatch', details: { noPrincipalElement: true } }
}
