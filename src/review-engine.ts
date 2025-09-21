import type {
	Config,
	DependencyChange,
	ComparisonResponse,
	ReviewResults,
} from "./types.js";
import { ScorecardService } from "./scorecard.js";
import * as spdx from "./spdx.js";

/**
 * A class that analyzes the dependencies and vulnerabilities in a PR
 */
export class ReviewEngine {
	constructor(private config: Config) {}

	/**
	 * Analyze the dependencies and vulnerabilities in a PR
	 * @param comparison - The comparison response
	 * @returns The review results
	 */
	async analyze(comparison: ComparisonResponse): Promise<ReviewResults> {
		const changes = comparison.changes;

		const vulnerableChanges = this.config.vulnerabilityCheck
			? this.filterVulnerableChanges(changes)
			: [];

		const invalidLicenseChanges = this.config.licenseCheck
			? this.filterInvalidLicenses(changes)
			: { forbidden: [], unresolved: [], unlicensed: [] };

		const deniedChanges = this.filterDeniedPackages(changes);

		const scorecardService = new ScorecardService();
		const scorecard = this.config.showOpenSSFScorecard
			? await scorecardService.getScorecardLevels(
					this.getScorecardChanges(changes),
				)
			: null;

		const hasIssues = this.determineHasIssues(
			vulnerableChanges,
			invalidLicenseChanges,
			deniedChanges,
		);

		const summary = this.generateSummary(changes, vulnerableChanges);

		return {
			vulnerableChanges,
			invalidLicenseChanges,
			deniedChanges,
			scorecard,
			hasIssues,
			summary,
		};
	}

	/**
	 * Filter the vulnerable changes
	 * @param changes - The changes to filter
	 * @returns The filtered changes
	 */
	private filterVulnerableChanges(
		changes: DependencyChange[],
	): DependencyChange[] {
		const severityOrder: Record<string, number> = {
			low: 0,
			moderate: 1,
			high: 2,
			critical: 3,
		};

		const minSeverityLevel = severityOrder[this.config.failOnSeverity];

		return changes.filter((change) => {
			if (change.change_type !== "added") {
				return false;
			}
			if (change.scope && !this.config.failOnScopes.includes(change.scope)) {
				return false;
			}

			return change.vulnerabilities.some((vuln) => {
				if (this.config.ghsas?.allow?.includes(vuln.advisory_ghsa_id)) {
					return false;
				}

				return severityOrder[vuln.severity] >= minSeverityLevel;
			});
		});
	}

	/**
	 * Filter the invalid licenses
	 * @param changes - The changes to filter
	 * @returns The filtered changes
	 */
	private filterInvalidLicenses(changes: DependencyChange[]): {
		forbidden: DependencyChange[];
		unresolved: DependencyChange[];
		unlicensed: DependencyChange[];
	} {
		const forbidden: DependencyChange[] = [];
		const unresolved: DependencyChange[] = [];
		const unlicensed: DependencyChange[] = [];

		for (const change of changes) {
			if (change.change_type !== "added") continue;

			if (!change.license) {
				unlicensed.push(change);
				continue;
			}

			const isPackageInLicenseExclusions = this.isPackageInLicenseExclusions(
				change.package_url,
			);
			if (this.config.licenseCheckExclusions && isPackageInLicenseExclusions) {
				continue;
			}

			if (change.license === "NOASSERTION") {
				unlicensed.push(change);
				continue;
			}

			try {
				if (
					this.config.licenses?.allow &&
					this.config.licenses.allow.length > 0
				) {
					if (spdx.isValid(change.license)) {
						const found = spdx.satisfies(
							change.license,
							this.config.licenses.allow.join(" OR "),
						);
						if (!found) {
							forbidden.push(change);
						}
					} else {
						unresolved.push(change);
					}
				} else if (
					this.config.licenses?.deny &&
					this.config.licenses.deny.length > 0
				) {
					if (spdx.isValid(change.license)) {
						const found = spdx.satisfiesAny(
							change.license,
							this.config.licenses.deny,
						);
						if (found) {
							forbidden.push(change);
						}
					} else {
						unresolved.push(change);
					}
				}
			} catch {
				unresolved.push(change);
			}
		}

		return { forbidden, unresolved, unlicensed };
	}

	/**
	 * Filter the denied packages
	 * @param changes - The changes to filter
	 * @returns The filtered changes
	 */
	private filterDeniedPackages(
		changes: DependencyChange[],
	): DependencyChange[] {
		if (
			(!this.config.packages?.deny || this.config.packages.deny.length === 0) &&
			(!this.config.groups?.deny || this.config.groups.deny.length === 0)
		) {
			return [];
		}

		return changes.filter((change) => {
			if (change.change_type !== "added") return false;

			if (this.config.packages?.deny) {
				for (const deniedPackage of this.config.packages.deny) {
					if (change.package_url.includes(deniedPackage)) {
						return true;
					}
				}
			}

			if (this.config.groups?.deny) {
				for (const deniedGroup of this.config.groups.deny) {
					if (change.package_url.startsWith(deniedGroup)) {
						return true;
					}
				}
			}

			return false;
		});
	}

	/**
	 * Check if a package is in the license exclusions
	 * @param packageUrl - The package URL
	 * @returns True if the package is in the license exclusions
	 */
	private isPackageInLicenseExclusions(packageUrl: string): boolean {
		if (
			!this.config.licenseCheckExclusions ||
			this.config.licenseCheckExclusions.length === 0
		) {
			return false;
		}

		for (const excludedPackage of this.config.licenseCheckExclusions) {
			if (
				packageUrl === excludedPackage ||
				packageUrl.startsWith(excludedPackage)
			) {
				return true;
			}

			const pkgWithoutVersion = packageUrl.split("@")[0];
			if (
				pkgWithoutVersion === excludedPackage ||
				(excludedPackage.endsWith("/") &&
					pkgWithoutVersion.startsWith(excludedPackage))
			) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Determine if there are any issues
	 * @param vulnerableChanges - The vulnerable changes
	 * @param invalidLicenseChanges - The invalid license changes
	 * @param deniedChanges - The denied changes
	 * @returns True if there are any issues
	 */
	private determineHasIssues(
		vulnerableChanges: DependencyChange[],
		invalidLicenseChanges: {
			forbidden: DependencyChange[];
			unresolved: DependencyChange[];
			unlicensed: DependencyChange[];
		},
		deniedChanges: DependencyChange[],
	): boolean {
		if (this.config.warnOnly) {
			return false;
		}

		return (
			vulnerableChanges.length > 0 ||
			invalidLicenseChanges.forbidden.length > 0 ||
			invalidLicenseChanges.unresolved.length > 0 ||
			deniedChanges.length > 0
		);
	}

	/**
	 * Get the scorecard changes
	 * @param changes - The changes to get the scorecard changes for
	 * @returns The scorecard changes
	 */
	private getScorecardChanges(changes: DependencyChange[]): DependencyChange[] {
		return changes.filter((change) => change.change_type === "added");
	}

	/**
	 * Generate the summary
	 * @param allChanges - The all changes
	 * @param vulnerableChanges - The vulnerable changes
	 * @returns The summary
	 */
	private generateSummary(
		allChanges: DependencyChange[],
		vulnerableChanges: DependencyChange[],
	) {
		const added = allChanges.filter((c) => c.change_type === "added").length;
		const removed = allChanges.filter(
			(c) => c.change_type === "removed",
		).length;

		const vulnCounts = { critical: 0, high: 0, moderate: 0, low: 0 };
		let totalVulns = 0;

		for (const change of vulnerableChanges) {
			for (const vuln of change.vulnerabilities) {
				vulnCounts[vuln.severity]++;
				totalVulns++;
			}
		}

		return {
			totalChanges: allChanges.length,
			added,
			removed,
			vulnerabilities: totalVulns,
			criticalVulns: vulnCounts.critical,
			highVulns: vulnCounts.high,
			moderateVulns: vulnCounts.moderate,
			lowVulns: vulnCounts.low,
		};
	}
}
