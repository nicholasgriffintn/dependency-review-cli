import type { Config, DependencyChange, ComparisonResponse, ScorecardData } from './types.js'
import { getScorecardLevels } from './scorecard.js'

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

export class ReviewEngine {
  constructor(private config: Config) {}

  async analyze(comparison: ComparisonResponse): Promise<ReviewResults> {
    const changes = comparison.changes
    
    const vulnerableChanges = this.config.vulnerabilityCheck 
      ? this.filterVulnerableChanges(changes)
      : []
    
    const invalidLicenseChanges = this.config.licenseCheck
      ? this.filterInvalidLicenses(changes)
      : { forbidden: [], unresolved: [], unlicensed: [] }
    
    const deniedChanges = this.filterDeniedPackages(changes)
    
    const scorecard = this.config.showOpenSSFScorecard 
      ? await getScorecardLevels(this.getScorecardChanges(changes))
      : null
    
    const hasIssues = this.determineHasIssues(vulnerableChanges, invalidLicenseChanges, deniedChanges)
    
    const summary = this.generateSummary(changes, vulnerableChanges)

    return {
      vulnerableChanges,
      invalidLicenseChanges,
      deniedChanges,
      scorecard,
      hasIssues,
      summary
    }
  }

  private filterVulnerableChanges(changes: DependencyChange[]): DependencyChange[] {
    const severityOrder: Record<string, number> = {
      low: 0,
      moderate: 1,
      high: 2,
      critical: 3
    }

    const minSeverityLevel = severityOrder[this.config.failOnSeverity]

    return changes.filter(change => {
      if (change.change_type !== 'added') {
        return false
      }
      if (change.scope && !this.config.failOnScopes.includes(change.scope)) {
        return false
      }
      
      return change.vulnerabilities.some(vuln => {
        if (this.config.allowGhsas.includes(vuln.advisory_ghsa_id)) {
          return false
        }
        
        return severityOrder[vuln.severity] >= minSeverityLevel
      })
    })
  }

  private filterInvalidLicenses(changes: DependencyChange[]): {
    forbidden: DependencyChange[]
    unresolved: DependencyChange[]
    unlicensed: DependencyChange[]
  } {
    const forbidden: DependencyChange[] = []
    const unresolved: DependencyChange[] = []
    const unlicensed: DependencyChange[] = []

    for (const change of changes) {
      if (change.change_type !== 'added') continue

      if (!change.license) {
        unlicensed.push(change)
        continue
      }

      const isPackageInLicenseExclusions = this.isPackageInLicenseExclusions(change.package_url)
      if (this.config.allowDependenciesLicenses && isPackageInLicenseExclusions) {
        continue
      }

      if (this.config.allowLicenses) {
        if (!this.config.allowLicenses.includes(change.license)) {
          forbidden.push(change)
        }
      } else if (this.config.denyLicenses) {
        if (this.config.denyLicenses.includes(change.license)) {
          forbidden.push(change)
        }
      }
    }

    return { forbidden, unresolved, unlicensed }
  }

  private filterDeniedPackages(changes: DependencyChange[]): DependencyChange[] {
    if (!this.config.denyPackages.length && !this.config.denyGroups.length) {
      return []
    }

    return changes.filter(change => {
      if (change.change_type !== 'added') return false

      for (const deniedPackage of this.config.denyPackages) {
        if (change.package_url.includes(deniedPackage)) {
          return true
        }
      }

      for (const deniedGroup of this.config.denyGroups) {
        if (change.package_url.startsWith(deniedGroup)) {
          return true
        }
      }

      return false
    })
  }

  private isPackageInLicenseExclusions(packageUrl: string): boolean {
    if (!this.config.allowDependenciesLicenses || this.config.allowDependenciesLicenses.length === 0) {
      return false
    }

    for (const excludedPackage of this.config.allowDependenciesLicenses) {
      if (packageUrl === excludedPackage || packageUrl.startsWith(excludedPackage)) {
        return true
      }
      
      const pkgWithoutVersion = packageUrl.split('@')[0]
      if (pkgWithoutVersion === excludedPackage || excludedPackage.endsWith('/') && pkgWithoutVersion.startsWith(excludedPackage)) {
        return true
      }
    }

    return false
  }

  private determineHasIssues(
    vulnerableChanges: DependencyChange[],
    invalidLicenseChanges: { forbidden: DependencyChange[], unresolved: DependencyChange[], unlicensed: DependencyChange[] },
    deniedChanges: DependencyChange[]
  ): boolean {
    if (this.config.warnOnly) return false

    return (
      vulnerableChanges.length > 0 ||
      invalidLicenseChanges.forbidden.length > 0 ||
      invalidLicenseChanges.unresolved.length > 0 ||
      deniedChanges.length > 0
    )
  }

  private getScorecardChanges(changes: DependencyChange[]): DependencyChange[] {
    return changes.filter(change => change.change_type === 'added')
  }

  private generateSummary(
    allChanges: DependencyChange[],
    vulnerableChanges: DependencyChange[]
  ) {
    const added = allChanges.filter(c => c.change_type === 'added').length
    const removed = allChanges.filter(c => c.change_type === 'removed').length
    
    const vulnCounts = { critical: 0, high: 0, moderate: 0, low: 0 }
    let totalVulns = 0

    for (const change of vulnerableChanges) {
      for (const vuln of change.vulnerabilities) {
        vulnCounts[vuln.severity]++
        totalVulns++
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
      lowVulns: vulnCounts.low
    }
  }
}
