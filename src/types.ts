export interface CliOptions {
  owner: string
  repo: string
  baseRef: string
  headRef: string
  config?: string
  output?: 'json' | 'table' | 'summary'
  failOnSeverity?: 'critical' | 'high' | 'moderate' | 'low'
  warnOnly?: boolean
  commentSummaryInPr?: 'always' | 'on-failure' | 'never'
  prNumber?: number
}

export interface DependencyChange {
  change_type: 'added' | 'removed'
  manifest: string
  ecosystem: string
  name: string
  version: string
  package_url: string
  license: string | null
  source_repository_url: string | null
  scope?: 'unknown' | 'runtime' | 'development'
  vulnerabilities: Vulnerability[]
}

export interface Vulnerability {
  severity: 'critical' | 'high' | 'moderate' | 'low'
  advisory_ghsa_id: string
  advisory_summary: string
  advisory_url: string
}

export interface ComparisonResponse {
  changes: DependencyChange[]
  snapshot_warnings: string
}

export interface Config {
  failOnSeverity: 'critical' | 'high' | 'moderate' | 'low'
  failOnScopes: ('unknown' | 'runtime' | 'development')[]
  allowLicenses?: string[]
  denyLicenses?: string[]
  allowDependenciesLicenses?: string[]
  allowGhsas: string[]
  denyPackages: string[]
  denyGroups: string[]
  licenseCheck: boolean
  vulnerabilityCheck: boolean
  warnOnly: boolean
  showOpenSSFScorecard: boolean
  warnOnOpenSSFScorecardLevel: number
}

export interface ScorecardEntry {
  change: DependencyChange
  scorecard: any | null
}

export interface ScorecardData {
  dependencies: ScorecardEntry[]
}

interface ScorecardCheck {
  name: string
  documentation: {
    shortDescription: string
    url: string
  }
  score: string
  reason: string
  details: string[]
}

export interface ScorecardResponse {
  score: number
  date: string
  repo: {
    name: string
    commit: string
  }
  checks: ScorecardCheck[]
}

export interface ReviewResults {
  vulnerableChanges: DependencyChange[]
  invalidLicenseChanges: {
    forbidden: DependencyChange[]
    unresolved: DependencyChange[]
    unlicensed: DependencyChange[]
  }
  deniedChanges: DependencyChange[]
  scorecard: ScorecardData | null
  hasIssues: boolean
  summary: {
    totalChanges: number
    added: number
    removed: number
    vulnerabilities: number
    criticalVulns: number
    highVulns: number
    moderateVulns: number
    lowVulns: number
  }
}
