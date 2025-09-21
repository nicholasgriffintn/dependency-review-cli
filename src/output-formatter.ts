import type { ComparisonResponse, ReviewResults } from "./types.js";

/**
 * A class that formats the output of the CLI for different formats
 */
export class OutputFormatter {
	constructor(
		private outputFormat: "json" | "table" | "markdown" | "summary",
	) {}

	/**
	 * Format the output of the CLI for different formats
	 * @param results - The results of the CLI
	 * @param comparison - The comparison response
	 * @returns The formatted output
	 */
	format(results: ReviewResults, comparison: ComparisonResponse): string {
		switch (this.outputFormat) {
			case "json":
				return this.formatJson(results, comparison);
			case "table":
				return this.formatTable(results);
			case "markdown":
				return this.formatMarkdown(results, comparison);
			case "summary":
				return this.formatSummary(results, comparison);
			default:
				return this.formatSummary(results, comparison);
		}
	}

	/**
	 * Format the output of the CLI for JSON
	 * @param results - The results of the CLI
	 * @param comparison - The comparison response
	 * @returns The formatted output
	 */
	private formatJson(
		results: ReviewResults,
		comparison: ComparisonResponse,
	): string {
		return JSON.stringify(
			{
				summary: results.summary,
				vulnerableChanges: results.vulnerableChanges,
				invalidLicenseChanges: results.invalidLicenseChanges,
				deniedChanges: results.deniedChanges,
				scorecard: results.scorecard,
				snapshotWarnings: comparison.snapshot_warnings,
				hasIssues: results.hasIssues,
			},
			null,
			2,
		);
	}

	/**
	 * Format the output of the CLI for a table
	 * @param results - The results of the CLI
	 * @returns The formatted output
	 */
	private formatTable(results: ReviewResults): string {
		let output = "";

		output += "\n📊 Dependency Review Summary\n";
		output += `Total Changes: ${results.summary.totalChanges}\n`;
		output += `Added: ${results.summary.added}\n`;
		output += `Removed: ${results.summary.removed}\n`;
		output += `Vulnerabilities: ${results.summary.vulnerabilities}\n`;
		output += `Critical: ${results.summary.criticalVulns}\n`;
		output += `High: ${results.summary.highVulns}\n`;
		output += `Moderate: ${results.summary.moderateVulns}\n`;
		output += `Low: ${results.summary.lowVulns}\n`;

		if (results.vulnerableChanges.length > 0) {
			output += "\n🚨 Vulnerable Dependencies\n";
			for (const change of results.vulnerableChanges) {
				for (const vuln of change.vulnerabilities) {
					output += `${change.name}@${change.version} - ${vuln.severity.toUpperCase()} - ${vuln.advisory_ghsa_id}\n`;
					output += `  ${vuln.advisory_summary}\n`;
				}
			}
		}

		if (results.invalidLicenseChanges.forbidden.length > 0) {
			output += "\n⚖️ License Issues\n";
			for (const change of results.invalidLicenseChanges.forbidden) {
				output += `${change.name}@${change.version} - License: ${change.license || "Unknown"} (Forbidden)\n`;
			}
		}

		if (results.invalidLicenseChanges.unresolved.length > 0) {
			output += "\n⚠️ Invalid SPDX License Expressions\n";
			for (const change of results.invalidLicenseChanges.unresolved) {
				output += `${change.name}@${change.version} - License: ${change.license || "Unknown"} (Invalid SPDX)\n`;
			}
		}

		if (results.scorecard && results.scorecard.dependencies.length > 0) {
			const lowScorePackages = results.scorecard.dependencies.filter(
				(entry) =>
					entry.scorecard &&
					entry.scorecard.score !== undefined &&
					entry.scorecard.score < 5,
			);

			if (lowScorePackages.length > 0) {
				output += "\n📊 Security Score Concerns\n";
				output += `${lowScorePackages.length} packages with low security scores (< 5.0/10):\n`;

				for (const entry of lowScorePackages) {
					output += `${entry.change.name}@${entry.change.version} - Score: ${entry.scorecard.score}/10\n`;
				}
			}
		}

		return output;
	}

	/**
	 * Format the output of the CLI for a markdown
	 * @param results - The results of the CLI
	 * @param comparison - The comparison response
	 * @returns The formatted output
	 */
	private formatMarkdown(
		results: ReviewResults,
		comparison: ComparisonResponse,
	): string {
		let output = "";

		const status = results.hasIssues ? "❌ Issues Found" : "✅ All Clear";
		const statusColor = results.hasIssues ? "#d73a49" : "#28a745";

		output += `## 🔍 Dependency Review Results\n\n`;
		output += `<div style="background: ${results.hasIssues ? "#fff5f5" : "#f0fff4"}; border: 1px solid ${statusColor}; border-radius: 6px; padding: 16px; margin: 12px 0;">\n`;
		output += `<h3 style="color: ${statusColor}; margin: 0 0 8px 0;">${status}</h3>\n`;
		output += `<strong>${results.summary.added} dependencies added</strong> • ${results.summary.removed} removed`;

		if (results.summary.vulnerabilities > 0) {
			const criticalText =
				results.summary.criticalVulns > 0
					? ` ${results.summary.criticalVulns} critical,`
					: "";
			const highText =
				results.summary.highVulns > 0
					? ` ${results.summary.highVulns} high,`
					: "";
			const moderateText =
				results.summary.moderateVulns > 0
					? ` ${results.summary.moderateVulns} moderate,`
					: "";
			const lowText =
				results.summary.lowVulns > 0 ? ` ${results.summary.lowVulns} low` : "";

			const vulnSummary =
				`${criticalText}${highText}${moderateText}${lowText}`.replace(/,$/, "");
			output += ` • <strong style="color: #d73a49;">${results.summary.vulnerabilities} vulnerabilities</strong> (${vulnSummary})`;
		}
		output += `\n</div>\n\n`;

		const criticalIssues = this.getCriticalIssues(results);
		if (criticalIssues.length > 0) {
			output += `### 🚨 Critical Issues\n\n`;
			for (const issue of criticalIssues) {
				output += `> **${issue.type}** ${issue.package} - ${issue.details}\n`;
			}
			output += `\n`;
		}

		if (results.vulnerableChanges.length > 0) {
			const vulnsByPackage = this.groupVulnerabilitiesByPackage(
				results.vulnerableChanges,
			);

			output += `### 🛡️ Security Vulnerabilities\n\n`;
			output += `<details>\n<summary><strong>${Object.keys(vulnsByPackage).length} packages with vulnerabilities</strong> (click to expand)</summary>\n\n`;

			for (const [packageName, data] of Object.entries(vulnsByPackage)) {
				const highestSeverity = this.getHighestSeverity(data.vulnerabilities);
				const severityIcon = this.getSeverityIcon(highestSeverity);
				const severityColor = this.getSeverityColor(highestSeverity);

				output += `#### ${severityIcon} ${packageName}@${data.version}\n`;
				output += `<span style="color: ${severityColor}; font-weight: bold;">${data.vulnerabilities.length} vulnerabilit${data.vulnerabilities.length === 1 ? "y" : "ies"}</span>\n\n`;

				for (const vuln of data.vulnerabilities) {
					output += `- **${vuln.severity.toUpperCase()}**: ${vuln.advisory_summary}\n`;
					output += `  📋 [${vuln.advisory_ghsa_id}](${vuln.advisory_url})\n\n`;
				}
			}
			output += `</details>\n\n`;
		}

		if (
			results.invalidLicenseChanges.forbidden.length > 0 ||
			results.invalidLicenseChanges.unresolved.length > 0 ||
			results.invalidLicenseChanges.unlicensed.length > 0
		) {
			output += `### ⚖️ License Issues\n\n`;

			if (results.invalidLicenseChanges.forbidden.length > 0) {
				output += `**Forbidden licenses:**\n`;
				for (const change of results.invalidLicenseChanges.forbidden) {
					output += `- ${change.name}@${change.version} (${change.license})\n`;
				}
				output += `\n`;
			}

			if (results.invalidLicenseChanges.unresolved.length > 0) {
				output += `**Invalid SPDX expressions:**\n`;
				for (const change of results.invalidLicenseChanges.unresolved) {
					output += `- ${change.name}@${change.version} (${change.license || "Unknown"})\n`;
				}
				output += `\n`;
			}

			if (results.invalidLicenseChanges.unlicensed.length > 0) {
				output += `**Unknown licenses:**\n`;
				for (const change of results.invalidLicenseChanges.unlicensed) {
					output += `- ${change.name}@${change.version}\n`;
				}
				output += `\n`;
			}
		}

		if (results.deniedChanges.length > 0) {
			output += `### 🚫 Denied Dependencies\n\n`;
			for (const change of results.deniedChanges) {
				output += `- ${change.name}@${change.version}\n`;
			}
			output += `\n`;
		}

		if (results.scorecard && results.scorecard.dependencies.length > 0) {
			const lowScorePackages = results.scorecard.dependencies.filter(
				(entry) =>
					entry.scorecard &&
					entry.scorecard.score !== undefined &&
					entry.scorecard.score < 5,
			);

			if (lowScorePackages.length > 0) {
				output += `### 📊 Security Score Concerns\n\n`;
				output += `<details>\n<summary><strong>${lowScorePackages.length} packages with low security scores</strong> (< 5.0/10)</summary>\n\n`;

				const ranges = {
					"0-2": lowScorePackages.filter((p) => p.scorecard.score < 2),
					"2-3": lowScorePackages.filter(
						(p) => p.scorecard.score >= 2 && p.scorecard.score < 3,
					),
					"3-4": lowScorePackages.filter(
						(p) => p.scorecard.score >= 3 && p.scorecard.score < 4,
					),
					"4-5": lowScorePackages.filter(
						(p) => p.scorecard.score >= 4 && p.scorecard.score < 5,
					),
				};

				for (const [range, packages] of Object.entries(ranges)) {
					if (packages.length > 0) {
						output += `**Score ${range}:**\n`;
						for (const entry of packages) {
							output += `- ${entry.change.name}@${entry.change.version} (${entry.scorecard.score}/10)\n`;
						}
						output += `\n`;
					}
				}
				output += `</details>\n\n`;
			}
		}

		if (comparison.snapshot_warnings) {
			output += `### ⚠️ Snapshot Warnings\n\n`;
			output += `\`\`\`\n${comparison.snapshot_warnings}\n\`\`\`\n\n`;
		}

		if (results.hasIssues) {
			output += `---\n\n`;
			output += `**Next Steps:**\n`;
			output += `- Review and address critical security vulnerabilities\n`;
			output += `- Check license compatibility with your project\n`;
			output += `- Consider alternatives for packages with very low security scores\n`;
		}

		return output;
	}

	/**
	 * Format the output of the CLI for a summary
	 * @param results - The results of the CLI
	 * @param comparison - The comparison response
	 * @returns The formatted output
	 */
	private formatSummary(
		results: ReviewResults,
		comparison: ComparisonResponse,
	): string {
		let output = "";

		const status = results.hasIssues ? "❌ Issues Found" : "✅ All Clear";
		const statusIcon = results.hasIssues ? "❌" : "✅";

		output += `\n🔍 Dependency Review Results\n`;
		output += `${statusIcon} ${status}\n`;
		output += `📊 ${results.summary.added} dependencies added • ${results.summary.removed} removed`;

		if (results.summary.vulnerabilities > 0) {
			const vulnText =
				results.summary.vulnerabilities === 1
					? "vulnerability"
					: "vulnerabilities";
			const vulnDetails = [];

			if (results.summary.criticalVulns > 0) {
				vulnDetails.push(`${results.summary.criticalVulns} critical`);
			}
			if (results.summary.highVulns > 0) {
				vulnDetails.push(`${results.summary.highVulns} high`);
			}
			if (results.summary.moderateVulns > 0) {
				vulnDetails.push(`${results.summary.moderateVulns} moderate`);
			}
			if (results.summary.lowVulns > 0) {
				vulnDetails.push(`${results.summary.lowVulns} low`);
			}

			output += ` • 🚨 ${results.summary.vulnerabilities} ${vulnText} (${vulnDetails.join(", ")})`;
		}
		output += "\n";

		const criticalIssues = this.getCriticalIssues(results);
		if (criticalIssues.length > 0) {
			output += "\n🚨 Critical Issues\n";
			for (const issue of criticalIssues) {
				output += `  ${issue.type} ${issue.package} - ${issue.details}\n`;
			}
		}

		if (results.vulnerableChanges.length > 0) {
			const vulnsByPackage = this.groupVulnerabilitiesByPackage(
				results.vulnerableChanges,
			);

			output += "\n🛡️ Security Vulnerabilities\n";
			output += `${Object.keys(vulnsByPackage).length} packages with vulnerabilities:\n`;

			for (const [packageName, data] of Object.entries(vulnsByPackage)) {
				const highestSeverity = this.getHighestSeverity(data.vulnerabilities);
				const severityIcon = this.getSeverityIcon(highestSeverity);

				output += `  ${severityIcon} ${packageName}@${data.version} - ${data.vulnerabilities.length} ${data.vulnerabilities.length === 1 ? "vulnerability" : "vulnerabilities"}\n`;

				for (const vuln of data.vulnerabilities) {
					output += `    ${vuln.severity.toUpperCase()}: ${vuln.advisory_summary}\n`;
					output += `    📋 ${vuln.advisory_ghsa_id}\n`;
				}
			}
		}

		if (
			results.invalidLicenseChanges.forbidden.length > 0 ||
			results.invalidLicenseChanges.unresolved.length > 0 ||
			results.invalidLicenseChanges.unlicensed.length > 0
		) {
			output += "\n⚖️ License Issues\n";

			if (results.invalidLicenseChanges.forbidden.length > 0) {
				output += `  Forbidden licenses:\n`;
				for (const change of results.invalidLicenseChanges.forbidden) {
					output += `    ${change.name}@${change.version} (${change.license})\n`;
				}
			}

			if (results.invalidLicenseChanges.unresolved.length > 0) {
				output += `  Invalid SPDX expressions:\n`;
				for (const change of results.invalidLicenseChanges.unresolved) {
					output += `    ${change.name}@${change.version} (${change.license || "Unknown"})\n`;
				}
			}

			if (results.invalidLicenseChanges.unlicensed.length > 0) {
				output += `  Unknown licenses:\n`;
				for (const change of results.invalidLicenseChanges.unlicensed) {
					output += `    ${change.name}@${change.version}\n`;
				}
			}
		}

		if (results.deniedChanges.length > 0) {
			output += "\n🚫 Denied Dependencies\n";
			for (const change of results.deniedChanges) {
				output += `  ${change.name}@${change.version}\n`;
			}
		}

		if (results.scorecard && results.scorecard.dependencies.length > 0) {
			const lowScorePackages = results.scorecard.dependencies.filter(
				(entry) =>
					entry.scorecard &&
					entry.scorecard.score !== undefined &&
					entry.scorecard.score < 5,
			);

			if (lowScorePackages.length > 0) {
				output += "\n📊 Security Score Concerns\n";
				output += `${lowScorePackages.length} packages with low security scores (< 5.0/10):\n`;

				const ranges = {
					"0-2": lowScorePackages.filter((p) => p.scorecard.score < 2),
					"2-3": lowScorePackages.filter(
						(p) => p.scorecard.score >= 2 && p.scorecard.score < 3,
					),
					"3-4": lowScorePackages.filter(
						(p) => p.scorecard.score >= 3 && p.scorecard.score < 4,
					),
					"4-5": lowScorePackages.filter(
						(p) => p.scorecard.score >= 4 && p.scorecard.score < 5,
					),
				};

				for (const [range, packages] of Object.entries(ranges)) {
					if (packages.length > 0) {
						output += `  Score ${range}:\n`;
						for (const entry of packages) {
							output += `    ${entry.change.name}@${entry.change.version} (${entry.scorecard.score}/10)\n`;
						}
					}
				}
			}
		}

		if (comparison.snapshot_warnings) {
			output += "\n⚠️ Snapshot Warnings\n";
			output += `${comparison.snapshot_warnings}\n`;
		}

		if (results.hasIssues) {
			output += "\n📝 Next Steps:\n";
			output += "  • Review and address critical security vulnerabilities\n";
			output += "  • Check license compatibility with your project\n";
			output +=
				"  • Consider alternatives for packages with very low security scores\n";
		}

		return output;
	}

	/**
	 * Get the critical issues from the results
	 * @param results - The results of the CLI
	 * @returns The critical issues
	 */
	private getCriticalIssues(
		results: ReviewResults,
	): Array<{ type: string; package: string; details: string }> {
		const critical = [];

		for (const change of results.vulnerableChanges) {
			const criticalVulns = change.vulnerabilities.filter(
				(v) => v.severity === "critical",
			);
			if (criticalVulns.length > 0) {
				critical.push({
					type: "🔴 CRITICAL",
					package: `${change.name}@${change.version}`,
					details: `${criticalVulns.length} critical vulnerabilit${criticalVulns.length === 1 ? "y" : "ies"}`,
				});
			}
		}

		for (const change of results.invalidLicenseChanges.forbidden) {
			critical.push({
				type: "⚖️ LICENSE",
				package: `${change.name}@${change.version}`,
				details: `Forbidden license: ${change.license}`,
			});
		}

		for (const change of results.deniedChanges) {
			critical.push({
				type: "🚫 DENIED",
				package: `${change.name}@${change.version}`,
				details: "Package is explicitly denied",
			});
		}

		return critical;
	}

	/**
	 * Group the vulnerabilities by package
	 * @param vulnerableChanges - The vulnerable changes
	 * @returns The grouped vulnerabilities
	 */
	private groupVulnerabilitiesByPackage(
		vulnerableChanges: any[],
	): Record<string, any> {
		const grouped: Record<string, any> = {};

		for (const change of vulnerableChanges) {
			const key = change.name;
			if (!grouped[key]) {
				grouped[key] = {
					version: change.version,
					vulnerabilities: [],
				};
			}

			const existingIds = new Set(
				grouped[key].vulnerabilities.map((v: any) => v.advisory_ghsa_id),
			);
			for (const vuln of change.vulnerabilities) {
				if (!existingIds.has(vuln.advisory_ghsa_id)) {
					grouped[key].vulnerabilities.push(vuln);
					existingIds.add(vuln.advisory_ghsa_id);
				}
			}
		}

		return grouped;
	}

	/**
	 * Get the highest severity from the vulnerabilities
	 * @param vulnerabilities - The vulnerabilities
	 * @returns The highest severity
	 */
	private getHighestSeverity(vulnerabilities: any[]): string {
		const severityOrder: Record<string, number> = {
			critical: 4,
			high: 3,
			moderate: 2,
			low: 1,
		};
		return vulnerabilities.reduce((highest, vuln) => {
			const vulnSeverity = vuln.severity as string;
			const currentSeverity = severityOrder[vulnSeverity] || 0;
			const highestSeverity = severityOrder[highest] || 0;
			return currentSeverity > highestSeverity ? vulnSeverity : highest;
		}, "low");
	}

	/**
	 * Get the severity icon from the severity
	 * @param severity - The severity
	 * @returns The severity icon
	 */
	private getSeverityIcon(severity: string): string {
		switch (severity) {
			case "critical":
				return "🔴";
			case "high":
				return "🟠";
			case "moderate":
				return "🟡";
			case "low":
				return "🟢";
			default:
				return "⚪";
		}
	}

	/**
	 * Get the severity color from the severity
	 * @param severity - The severity
	 * @returns The severity color
	 */
	private getSeverityColor(severity: string): string {
		switch (severity) {
			case "critical":
				return "#d73a49";
			case "high":
				return "#f66a0a";
			case "moderate":
				return "#ffd33d";
			case "low":
				return "#28a745";
			default:
				return "#6a737d";
		}
	}
}
