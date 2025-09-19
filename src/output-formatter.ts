import type { ReviewResults } from './review-engine.js'
import type { ComparisonResponse } from './types.js'

export class OutputFormatter {
  constructor(private outputFormat: 'json' | 'table' | 'summary') {}

  format(results: ReviewResults, comparison: ComparisonResponse): string {
    switch (this.outputFormat) {
      case 'json':
        return this.formatJson(results, comparison)
      case 'table':
        return this.formatTable(results)
      case 'summary':
      default:
        return this.formatSummary(results, comparison)
    }
  }

  private formatJson(results: ReviewResults, comparison: ComparisonResponse): string {
    return JSON.stringify({
      summary: results.summary,
      vulnerableChanges: results.vulnerableChanges,
      invalidLicenseChanges: results.invalidLicenseChanges,
      deniedChanges: results.deniedChanges,
      snapshotWarnings: comparison.snapshot_warnings,
      hasIssues: results.hasIssues
    }, null, 2)
  }

  private formatTable(results: ReviewResults): string {
    let output = ''

    output += '\n📊 Dependency Review Summary\n'
    output += `Total Changes: ${results.summary.totalChanges}\n`
    output += `Added: ${results.summary.added}\n`
    output += `Removed: ${results.summary.removed}\n`
    output += `Vulnerabilities: ${results.summary.vulnerabilities}\n`
    output += `Critical: ${results.summary.criticalVulns}\n`
    output += `High: ${results.summary.highVulns}\n`
    output += `Moderate: ${results.summary.moderateVulns}\n`
    output += `Low: ${results.summary.lowVulns}\n`

    if (results.vulnerableChanges.length > 0) {
      output += '\n🚨 Vulnerable Dependencies\n'
      for (const change of results.vulnerableChanges) {
        for (const vuln of change.vulnerabilities) {
          output += `${change.name}@${change.version} - ${vuln.severity.toUpperCase()} - ${vuln.advisory_ghsa_id}\n`
          output += `  ${vuln.advisory_summary}\n`
        }
      }
    }

    if (results.invalidLicenseChanges.forbidden.length > 0) {
      output += '\n⚖️ License Issues\n'
      for (const change of results.invalidLicenseChanges.forbidden) {
        output += `${change.name}@${change.version} - License: ${change.license || 'Unknown'} (Forbidden)\n`
      }
    }

    return output
  }

  private formatSummary(results: ReviewResults, comparison: ComparisonResponse): string {
    let output = ''

    output += '\n🔍 Dependency Review Results\n'
    output += '═'.repeat(50) + '\n'

    output += '\n📊 Summary:\n'
    output += `• Total changes: ${results.summary.totalChanges}\n`
    output += `• Added: ${results.summary.added}\n`
    output += `• Removed: ${results.summary.removed}\n`
    
    if (results.summary.vulnerabilities > 0) {
      output += `• Vulnerabilities found: ${results.summary.vulnerabilities}\n`
      if (results.summary.criticalVulns > 0) {
        output += `  - Critical: ${results.summary.criticalVulns}\n`
      }
      if (results.summary.highVulns > 0) {
        output += `  - High: ${results.summary.highVulns}\n`
      }
      if (results.summary.moderateVulns > 0) {
        output += `  - Moderate: ${results.summary.moderateVulns}\n`
      }
      if (results.summary.lowVulns > 0) {
        output += `  - Low: ${results.summary.lowVulns}\n`
      }
    }

    if (results.vulnerableChanges.length > 0) {
      output += '\n🚨 Vulnerable Dependencies:\n'
      for (const change of results.vulnerableChanges) {
        output += `\n${change.manifest} » ${change.name}@${change.version}\n`
        for (const vuln of change.vulnerabilities) {
          output += `  [${vuln.severity.toUpperCase()}] ${vuln.advisory_summary}\n`
          output += `  ${vuln.advisory_url}\n`
        }
      }
    }

    if (results.invalidLicenseChanges.forbidden.length > 0) {
      output += '\n⚖️ License Issues:\n'
      for (const change of results.invalidLicenseChanges.forbidden) {
        output += `• ${change.name}@${change.version} - License: ${change.license || 'Unknown'}\n`
      }
    }

    if (results.invalidLicenseChanges.unlicensed.length > 0) {
      output += '\n❓ Dependencies with Unknown Licenses:\n'
      for (const change of results.invalidLicenseChanges.unlicensed) {
        output += `• ${change.name}@${change.version}\n`
      }
    }

    if (results.deniedChanges.length > 0) {
      output += '\n🚫 Denied Dependencies:\n'
      for (const change of results.deniedChanges) {
        output += `• ${change.name}@${change.version} is denied\n`
      }
    }

    if (comparison.snapshot_warnings) {
      output += '\n⚠️ Snapshot Warnings:\n'
      output += comparison.snapshot_warnings
    }

    if (results.scorecard && results.scorecard.dependencies.length > 0) {
      output += '\n📊 OpenSSF Scorecard:\n'
      for (const entry of results.scorecard.dependencies) {
        if (entry.scorecard && entry.scorecard.score !== undefined) {
          output += `• ${entry.change.name}@${entry.change.version} - Score: ${entry.scorecard.score}/10\n`
          if (entry.scorecard.score < 5) {
            output += `  ⚠️ Low security score\n`
          }
        }
      }
    }

    output += '\n' + '═'.repeat(50) + '\n'
    if (results.hasIssues) {
      output += '❌ Issues found - review failed\n'
    } else {
      output += '✅ No issues found - review passed\n'
    }

    return output
  }
}
