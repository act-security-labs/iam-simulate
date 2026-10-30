import { type ConditionValueExplain } from '../../explain/statementExplain.js'
import { resolveIamConditionString } from '../../util.js'
import { type BaseConditionOperator } from '../BaseConditionOperator.js'
import { resolvedValue } from '../conditionUtil.js'
import { ignoreCaseEquals } from './ignoreCaseEquals.js'

export const StringNotEqualsIgnoreCase: BaseConditionOperator = {
  name: 'StringNotEqualsIgnoreCase',
  matches: (request, keyValue, policyValues) => {
    const explains: ConditionValueExplain[] = policyValues.map((value) => {
      const { value: resolved, errors } = resolveIamConditionString(value, request)
      if (errors && errors.length > 0) {
        return {
          value,
          matches: false,
          errors
        }
      }

      const matches = !ignoreCaseEquals(resolved, keyValue)
      return {
        value,
        matches,
        resolvedValue: resolvedValue(value, request)
      }
    })

    const overallMatch = !explains.some((explain) => !explain.matches)
    return {
      matches: overallMatch,
      explains
    }
  },
  allowsVariables: true,
  allowsWildcards: false,
  isNegative: true
}
