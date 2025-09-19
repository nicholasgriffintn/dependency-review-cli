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

export interface CliOptions {
  owner: string
  repo: string
  baseRef: string
  headRef: string
  config?: string
  output?: 'json' | 'table' | 'summary'
  failOnSeverity?: 'critical' | 'high' | 'moderate' | 'low'
  warnOnly?: boolean
}
