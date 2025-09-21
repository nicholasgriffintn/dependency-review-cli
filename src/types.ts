/**
 * The options that can be passed to the CLI
 */
export interface CliOptions {
	/**
	 * The owner of the repository
	 */
	owner: string;
	/**
	 * The repository name
	 */
	repo: string;
	/**
	 * The base reference of the repository
	 */
	baseRef: string;
	/**
	 * The head reference of the repository
	 */
	headRef: string;
	/**
	 * The path to the configuration file
	 */
	config?: string;
	/**
	 * The output format
	 * @default 'summary'
	 */
	output?: "json" | "table" | "summary";
	/**
	 * The severity of the vulnerabilities that will cause the command to fail
	 * @default 'low'
	 */
	failOnSeverity?: "critical" | "high" | "moderate" | "low";
	/**
	 * Whether to only warn, never fail the command
	 * @default false
	 */
	warnOnly?: boolean;
	/**
	 * The mode for commenting the summary in the PR
	 * @default 'never'
	 */
	commentSummaryInPr?: "always" | "on-failure" | "never";
	/**
	 * The number of the PR to comment the summary in
	 */
	prNumber?: number;
}

export interface Config {
	/**
	 * The severity of the vulnerabilities that will cause the command to fail
	 * @default 'low'
	 */
	failOnSeverity: "critical" | "high" | "moderate" | "low";
	/**
	 * The scopes of the vulnerabilities that will cause the command to fail
	 * @default ['runtime']
	 */
	failOnScopes: ("unknown" | "runtime" | "development")[];
	/**
	 * Licenses that you want to error against, you can only specify one of allow or deny
	 * @default { allow: [], deny: [...default licenses] }
	 */
	licenses: {
		allow?: string[];
		deny?: string[];
	};
	/**
	 * Any packages that you would like to deny from being added
	 * @default { deny: [] }
	 */
	packages: {
		deny?: string[];
	};
	/**
	 * Any NPM groups that you would like to deny from being added
	 * @default { deny: [] }
	 */
	groups: {
		deny?: string[];
	};
	/**
	 * IDs of the vulnerabilities that you have accepted
	 * @default { allow: [] }
	 */
	ghsas: {
		allow?: string[];
	};
	/**
	 * Define packages here that should be excluded from the license check
	 * @default undefined
	 */
	licenseCheckExclusions?: string[];
	/**
	 * Whether to check the licenses
	 * @default true
	 */
	licenseCheck: boolean;
	/**
	 * Whether to check the vulnerabilities
	 * @default true
	 */
	vulnerabilityCheck: boolean;
	/**
	 * Whether to only warn, never fail the command
	 * @default false
	 */
	warnOnly: boolean;
	/**
	 * Whether to show the OpenSSF Scorecard
	 * @default true
	 */
	showOpenSSFScorecard: boolean;
	/**
	 * The level of the OpenSSF Scorecard that will cause the command to fail
	 * @default 3
	 */
	warnOnOpenSSFScorecardLevel: number;
}

export interface DependencyChange {
	change_type: "added" | "removed";
	manifest: string;
	ecosystem: string;
	name: string;
	version: string;
	package_url: string;
	license: string | null;
	source_repository_url: string | null;
	scope?: "unknown" | "runtime" | "development";
	vulnerabilities: Vulnerability[];
}

export interface Vulnerability {
	severity: "critical" | "high" | "moderate" | "low";
	advisory_ghsa_id: string;
	advisory_summary: string;
	advisory_url: string;
}

export interface ComparisonResponse {
	changes: DependencyChange[];
	snapshot_warnings: string;
}

export interface ScorecardEntry {
	change: DependencyChange;
	scorecard: any | null;
}

export interface ScorecardData {
	dependencies: ScorecardEntry[];
}

interface ScorecardCheck {
	name: string;
	documentation: {
		shortDescription: string;
		url: string;
	};
	score: string;
	reason: string;
	details: string[];
}

export interface ScorecardResponse {
	score: number;
	date: string;
	repo: {
		name: string;
		commit: string;
	};
	checks: ScorecardCheck[];
}

export interface ReviewResults {
	vulnerableChanges: DependencyChange[];
	invalidLicenseChanges: {
		forbidden: DependencyChange[];
		unresolved: DependencyChange[];
		unlicensed: DependencyChange[];
	};
	deniedChanges: DependencyChange[];
	scorecard: ScorecardData | null;
	hasIssues: boolean;
	summary: {
		totalChanges: number;
		added: number;
		removed: number;
		vulnerabilities: number;
		criticalVulns: number;
		highVulns: number;
		moderateVulns: number;
		lowVulns: number;
	};
}
