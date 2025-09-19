import { describe, it } from 'node:test'
import assert from 'node:assert'

import { OutputFormatter } from '../src/output-formatter.js'

const createMockResults = (overrides = {}) => ({
  vulnerableChanges: [],
  invalidLicenseChanges: {
    forbidden: [],
    unresolved: [],
    unlicensed: []
  },
  deniedChanges: [],
  scorecard: null,
  hasIssues: false,
  summary: {
    totalChanges: 1,
    added: 1,
    removed: 0,
    vulnerabilities: 0,
    criticalVulns: 0,
    highVulns: 0,
    moderateVulns: 0,
    lowVulns: 0
  },
  ...overrides
})

const mockComparison = {
  changes: [],
  snapshot_warnings: ''
}

describe('OutputFormatter', () => {
  it('should format JSON output', () => {
    const formatter = new OutputFormatter('json')
    const results = createMockResults()
    
    const output = formatter.format(results, mockComparison)
    const parsed = JSON.parse(output)

    assert.strictEqual(parsed.hasIssues, false)
    assert.strictEqual(parsed.summary.totalChanges, 1)
    assert.strictEqual(parsed.summary.added, 1)
  })

  it('should format table output', () => {
    const formatter = new OutputFormatter('table')
    const results = createMockResults({
      vulnerableChanges: [{
        name: 'vulnerable-pkg',
        version: '1.0.0',
        vulnerabilities: [{
          severity: 'high',
          advisory_ghsa_id: 'GHSA-1234',
          advisory_summary: 'Test vulnerability'
        }]
      }],
      summary: {
        ...createMockResults().summary,
        vulnerabilities: 1,
        highVulns: 1
      }
    })
    
    const output = formatter.format(results, mockComparison)

    assert(output.includes('📊 Dependency Review Summary'))
    assert(output.includes('Total Changes: 1'))
    assert(output.includes('Vulnerabilities: 1'))
    assert(output.includes('🚨 Vulnerable Dependencies'))
    assert(output.includes('vulnerable-pkg@1.0.0 - HIGH - GHSA-1234'))
  })

  it('should format summary output with issues', () => {
    const formatter = new OutputFormatter('summary')
    const results = createMockResults({
      hasIssues: true,
      vulnerableChanges: [{
        manifest: 'package.json',
        name: 'bad-package',
        version: '2.0.0',
        vulnerabilities: [{
          severity: 'critical',
          advisory_ghsa_id: 'GHSA-crit-5678',
          advisory_summary: 'Critical security flaw',
          advisory_url: 'https://github.com/advisories/GHSA-crit-5678'
        }]
      }],
      invalidLicenseChanges: {
        forbidden: [{
          name: 'licensed-pkg',
          version: '1.0.0',
          license: 'GPL-3.0'
        }],
        unresolved: [],
        unlicensed: [{
          name: 'no-license-pkg',
          version: '1.0.0'
        }]
      },
      summary: {
        ...createMockResults().summary,
        vulnerabilities: 1,
        criticalVulns: 1
      }
    })
    
    const output = formatter.format(results, mockComparison)

    assert(output.includes('🔍 Dependency Review Results'))
    assert(output.includes('🚨 Vulnerable Dependencies'))
    assert(output.includes('package.json » bad-package@2.0.0'))
    assert(output.includes('[CRITICAL] Critical security flaw'))
    assert(output.includes('⚖️ License Issues'))
    assert(output.includes('licensed-pkg@1.0.0 - License: GPL-3.0'))
    assert(output.includes('❓ Dependencies with Unknown Licenses'))
    assert(output.includes('no-license-pkg@1.0.0'))
    assert(output.includes('❌ Issues found - review failed'))
  })

  it('should format summary output without issues', () => {
    const formatter = new OutputFormatter('summary')
    const results = createMockResults()
    
    const output = formatter.format(results, mockComparison)

    assert(output.includes('🔍 Dependency Review Results'))
    assert(output.includes('• Total changes: 1'))
    assert(output.includes('• Added: 1'))
    assert(output.includes('• Removed: 0'))
    assert(output.includes('✅ No issues found - review passed'))
  })

  it('should include snapshot warnings in output', () => {
    const formatter = new OutputFormatter('summary')
    const results = createMockResults()
    const comparisonWithWarnings = {
      changes: [],
      snapshot_warnings: 'Warning: Some packages may not have complete data'
    }
    
    const output = formatter.format(results, comparisonWithWarnings)

    assert(output.includes('⚠️ Snapshot Warnings'))
    assert(output.includes('Warning: Some packages may not have complete data'))
  })

  it('should include OpenSSF Scorecard data in output', () => {
    const formatter = new OutputFormatter('summary')
    const results = createMockResults({
      scorecard: {
        dependencies: [{
          change: { name: 'test-pkg', version: '1.0.0' },
          scorecard: { score: 3.5 }
        }, {
          change: { name: 'good-pkg', version: '2.0.0' },
          scorecard: { score: 8.2 }
        }]
      }
    })
    
    const output = formatter.format(results, mockComparison)

    assert(output.includes('📊 OpenSSF Scorecard'))
    assert(output.includes('test-pkg@1.0.0 - Score: 3.5/10'))
    assert(output.includes('⚠️ Low security score'))
    assert(output.includes('good-pkg@2.0.0 - Score: 8.2/10'))
  })
})
