// Copied from https://github.com/actions/dependency-review-action/blob/main/src/spdx.ts

import * as spdxlib from "@onebeyond/spdx-license-satisfies";
import spdxSatisfies from "spdx-satisfies";
import parse from "spdx-expression-parse";

/*
 * NOTE: spdx-license-satisfies methods depend on spdx-expression-parse
 * which throws errors in the presence of any syntax trouble, unknown
 * license tokens, case sensitivity problems etc. to simplify handling
 * you should pre-screen inputs to the satisfies* methods using isValid
 */

/**
 * Check if an SPDX expression is valid
 * @param candidateExpr - The SPDX expression to check
 * @returns True if the SPDX expression is valid
 */
export function isValid(candidateExpr: string): boolean {
	try {
		parse(candidateExpr);
		return true;
	} catch (_) {
		return false;
	}
}

/**
 * Check if an SPDX expression satisfies any of the licenses
 * @param candidateExpr - The SPDX expression to check
 * @param licenses - The licenses to check
 * @returns True if the SPDX expression satisfies any of the licenses
 */
export function satisfiesAny(
	candidateExpr: string,
	licenses: string[],
): boolean {
	candidateExpr = cleanInvalidSPDX(candidateExpr);
	try {
		return spdxlib.satisfiesAny(candidateExpr, licenses);
	} catch (_) {
		return false;
	}
}

/**
 * Check if an SPDX expression satisfies all of the licenses
 * @param candidateExpr - The SPDX expression to check
 * @param licenses - The licenses to check
 * @returns True if the SPDX expression satisfies all of the licenses
 */
export function satisfiesAll(
	candidateExpr: string,
	licenses: string[],
): boolean {
	candidateExpr = cleanInvalidSPDX(candidateExpr);
	try {
		return spdxlib.satisfiesAll(candidateExpr, licenses);
	} catch (_) {
		return false;
	}
}

/**
 * Check if an SPDX expression satisfies a range
 * @param candidateExpr - The SPDX expression to check
 * @param range - The range to check
 * @returns True if the SPDX expression satisfies the range
 */
export function satisfies(candidateExpr: string, range: string): boolean {
	candidateExpr = cleanInvalidSPDX(candidateExpr);
	try {
		return spdxSatisfies(candidateExpr, range);
	} catch (_) {
		return false;
	}
}

/**
 * Clean an SPDX expression to not include the invalid `OTHER`
 * @param spdxExpr - The SPDX expression to clean
 * @returns The cleaned SPDX expression
 */
export function cleanInvalidSPDX(spdxExpr: string): string {
	const replaceOtherRegex = /(?<![\w-])OTHER(?![\w-])/g;

	return spdxExpr.replace(replaceOtherRegex, "LicenseRef-clearlydefined-OTHER");
}
