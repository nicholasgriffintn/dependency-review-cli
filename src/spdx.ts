// Copied from https://github.com/actions/dependency-review-action/blob/main/src/spdx.ts

import * as spdxlib from '@onebeyond/spdx-license-satisfies'
import spdxSatisfies from 'spdx-satisfies'
import parse from 'spdx-expression-parse'

/*
 * NOTE: spdx-license-satisfies methods depend on spdx-expression-parse
 * which throws errors in the presence of any syntax trouble, unknown
 * license tokens, case sensitivity problems etc. to simplify handling
 * you should pre-screen inputs to the satisfies* methods using isValid
 */

export function isValid(candidateExpr: string): boolean {
  try {
    parse(candidateExpr)
    return true
  } catch (_) {
    return false
  }
}

// accepts an SPDX expression and a non-empty list of licenses (not expressions)
export function satisfiesAny(
  candidateExpr: string,
  licenses: string[]
): boolean {
  candidateExpr = cleanInvalidSPDX(candidateExpr)
  try {
    return spdxlib.satisfiesAny(candidateExpr, licenses)
  } catch (_) {
    return false
  }
}

// accepts an SPDX expression and a non-empty list of licenses (not expressions)
export function satisfiesAll(
  candidateExpr: string,
  licenses: string[]
): boolean {
  candidateExpr = cleanInvalidSPDX(candidateExpr)
  try {
    return spdxlib.satisfiesAll(candidateExpr, licenses)
  } catch (_) {
    return false
  }
}

// simple pass-through for the underlying spdx-satisfies method
export function satisfies(candidateExpr: string, range: string): boolean {
  candidateExpr = cleanInvalidSPDX(candidateExpr)
  try {
    return spdxSatisfies(candidateExpr, range)
  } catch (_) {
    return false
  }
}

const replaceOtherRegex = /(?<![\w-])OTHER(?![\w-])/g

// adjusts license expressions to not include the invalid `OTHER`
// which ClearlyDefined adds to license strings
export function cleanInvalidSPDX(spdxExpr: string): string {
  return spdxExpr.replace(replaceOtherRegex, 'LicenseRef-clearlydefined-OTHER')
}
