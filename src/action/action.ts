import { type Action, type Statement } from '@actsecurity/iam-policy'
import { type ActionExplain, type StatementExplain } from '../explain/statementExplain.js'
import { type AwsRequest } from '../request/request.js'

const whitespaceRegex = /\s/

/**
 * Check if a request matches the Action or NotAction elements of a statement.
 *
 * @param request the request to check
 * @param statement the statement to check against
 * @returns true if the request matches the Action or NotAction in the statement, false otherwise
 */
export function requestMatchesStatementActions(
  request: AwsRequest,
  statement: Statement
): { matches: boolean; details: Pick<StatementExplain, 'actions' | 'notActions'> } {
  if (statement.isActionStatement()) {
    const { matches, explains } = requestMatchesActions(request, statement.actions())
    if (!statement.actionIsArray()) {
      return { matches, details: { actions: explains[0] } }
    }
    return { matches, details: { actions: explains } }
  } else if (statement.isNotActionStatement()) {
    const { matches, explains } = requestMatchesNotActions(request, statement.notActions())
    if (!statement.notActionIsArray()) {
      return { matches, details: { notActions: explains[0] } }
    }
    return { matches, details: { notActions: explains } }
  }
  throw new Error('Statement has neither Actions nor NotActions')
}

/**
 * Convert an action action (the part after the colon) to a regular expression.
 *
 * @param action the action to convert to a regular expression
 * @returns a regular that replaces any wildcards in the action with the appropriate regular expression.
 */
function convertActionToRegex(action: string): RegExp {
  if (action.indexOf(':') != -1) {
    throw new Error('Action should not contain a colon')
  }
  const pattern = '^' + action.replace(/\?/g, '.').replace(/\*/g, '.*?') + '$'
  return new RegExp(pattern, 'i')
}

/**
 * Check if a request matches a set of actions.
 *
 * @param request the request to check
 * @param actions the actions to check against
 * @returns true if the request matches any of the actions, false otherwise
 */
export function requestMatchesActions(
  request: AwsRequest,
  actions: Action[]
): { matches: boolean; explains: ActionExplain[] } {
  const explains = actions.map((action) => requestMatchesSingleAction(request, action))
  const matches = explains.some((explain) => explain.matches)
  return { matches, explains }
}

/**
 * Check if a request does not match a set of actions.
 *
 * @param request the request to check
 * @param actions the actions to check against
 * @returns true if the request does not match any of the actions, false if the request matches any of the actions
 */
export function requestMatchesNotActions(
  request: AwsRequest,
  actions: Action[]
): { matches: boolean; explains: ActionExplain[] } {
  const explains = actions.map((action) => {
    const explain = requestMatchesSingleAction(request, action)
    explain.matches = !explain.matches
    return explain
  })

  const matches = !explains.some((explain) => !explain.matches)
  return { matches, explains }
}

function requestMatchesSingleAction(request: AwsRequest, action: Action): ActionExplain {
  if (action.isWildcardAction()) {
    return {
      action: action.value(),
      matches: true
    }
  } else if (action.isServiceAction()) {
    const actionPart = action.action()
    if (actionPart.length === 0 || whitespaceRegex.test(actionPart)) {
      return {
        action: action.value(),
        matches: false
      }
    }
    if (request.action.service() != action.service()) {
      return {
        action: action.value(),
        matches: false
      }
    }
    const actionRegex = convertActionToRegex(actionPart)
    const matches = actionRegex.test(request.action.action())
    return {
      action: action.value(),
      matches
    }
  }
  throw new Error('Unknown action type')
}
