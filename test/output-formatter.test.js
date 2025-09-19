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

  it('should format summary output with critical vulnerability', () => {
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
      summary: {
        ...createMockResults().summary,
        vulnerabilities: 1,
        criticalVulns: 1
      }
    })
    
    const output = formatter.format(results, mockComparison)

    assert(output.includes('## 🔍 Dependency Review Results'))
    assert(output.includes('❌ Issues Found'))
    assert(output.includes('1 dependencies added'))
    assert(output.includes('1 vulnerabilities'))
    assert(output.includes('1 critical'))
    assert(output.includes('### 🚨 Critical Issues'))
    assert(output.includes('🔴 CRITICAL'))
    assert(output.includes('bad-package@2.0.0'))
    assert(output.includes('1 critical vulnerability'))
    assert(output.includes('### 🛡️ Security Vulnerabilities'))
    assert(output.includes('1 packages with vulnerabilities'))
    assert(output.includes('🔴 bad-package@2.0.0'))
    assert(output.includes('**CRITICAL**: Critical security flaw'))
    assert(output.includes('[GHSA-crit-5678]'))
    assert(output.includes('**Next Steps:**'))
  })

  it('should format summary output with license issues', () => {
    const formatter = new OutputFormatter('summary')
    const results = createMockResults({
      hasIssues: true,
      invalidLicenseChanges: {
        forbidden: [{
          name: 'licensed-pkg',
          version: '1.0.0',
          license: 'GPL-3.0'
        }],
        unresolved: [{
          name: 'bad-spdx-pkg',
          version: '1.0.0',
          license: 'Invalid-License'
        }],
        unlicensed: [{
          name: 'no-license-pkg',
          version: '1.0.0'
        }]
      }
    })
    
    const output = formatter.format(results, mockComparison)

    assert(output.includes('### 🚨 Critical Issues'))
    assert(output.includes('⚖️ LICENSE'))
    assert(output.includes('licensed-pkg@1.0.0'))
    assert(output.includes('Forbidden license: GPL-3.0'))
    assert(output.includes('### ⚖️ License Issues'))
    assert(output.includes('**Forbidden licenses:**'))
    assert(output.includes('licensed-pkg@1.0.0 (GPL-3.0)'))
    assert(output.includes('**Invalid SPDX expressions:**'))
    assert(output.includes('bad-spdx-pkg@1.0.0 (Invalid-License)'))
    assert(output.includes('**Unknown licenses:**'))
    assert(output.includes('no-license-pkg@1.0.0'))
  })

  it('should format summary output with denied packages', () => {
    const formatter = new OutputFormatter('summary')
    const results = createMockResults({
      hasIssues: true,
      deniedChanges: [{
        name: 'denied-pkg',
        version: '1.0.0'
      }]
    })
    
    const output = formatter.format(results, mockComparison)

    assert(output.includes('### 🚨 Critical Issues'))
    assert(output.includes('🚫 DENIED'))
    assert(output.includes('denied-pkg@1.0.0'))
    assert(output.includes('Package is explicitly denied'))
    assert(output.includes('### 🚫 Denied Dependencies'))
    assert(output.includes('denied-pkg@1.0.0'))
  })

  it('should format summary output without issues', () => {
    const formatter = new OutputFormatter('summary')
    const results = createMockResults()
    
    const output = formatter.format(results, mockComparison)

    assert(output.includes('## 🔍 Dependency Review Results'))
    assert(output.includes('✅ All Clear'))
    assert(output.includes('1 dependencies added'))
    assert(output.includes('0 removed'))
    assert(!output.includes('vulnerabilities'))
    assert(!output.includes('Critical Issues'))
    assert(!output.includes('Next Steps'))
  })

  it('should include snapshot warnings in output', () => {
    const formatter = new OutputFormatter('summary')
    const results = createMockResults()
    const comparisonWithWarnings = {
      changes: [],
      snapshot_warnings: 'Warning: Some packages may not have complete data'
    }
    
    const output = formatter.format(results, comparisonWithWarnings)

    assert(output.includes('### ⚠️ Snapshot Warnings'))
    assert(output.includes('Warning: Some packages may not have complete data'))
  })

  it('should include OpenSSF Scorecard data in output for low scores only', () => {
    const formatter = new OutputFormatter('summary')
    const results = createMockResults({
      scorecard: {
        dependencies: [{
          change: { name: 'test-pkg', version: '1.0.0' },
          scorecard: { score: 3.5 }
        }, {
          change: { name: 'good-pkg', version: '2.0.0' },
          scorecard: { score: 8.2 }
        }, {
          change: { name: 'very-bad-pkg', version: '1.5.0' },
          scorecard: { score: 1.2 }
        }]
      }
    })
    
    const output = formatter.format(results, mockComparison)

    assert(output.includes('### 📊 Security Score Concerns'))
    assert(output.includes('2 packages with low security scores'))
    assert(output.includes('< 5.0/10'))
    assert(output.includes('**Score 0-2:**'))
    assert(output.includes('very-bad-pkg@1.5.0 (1.2/10)'))
    assert(output.includes('**Score 3-4:**'))
    assert(output.includes('test-pkg@1.0.0 (3.5/10)'))
    assert(!output.includes('good-pkg@2.0.0'))
    assert(!output.includes('8.2/10'))
  })

  it('should not show scorecard section if no low scores', () => {
    const formatter = new OutputFormatter('summary')
    const results = createMockResults({
      scorecard: {
        dependencies: [{
          change: { name: 'good-pkg', version: '2.0.0' },
          scorecard: { score: 8.2 }
        }, {
          change: { name: 'another-good-pkg', version: '1.0.0' },
          scorecard: { score: 6.5 }
        }]
      }
    })
    
    const output = formatter.format(results, mockComparison)

    assert(!output.includes('📊 Security Score Concerns'))
    assert(!output.includes('low security scores'))
  })

  it('should group vulnerabilities by package and deduplicate', () => {
    const formatter = new OutputFormatter('summary')
    const results = createMockResults({
      hasIssues: true,
      vulnerableChanges: [
        {
          manifest: 'package.json',
          name: 'vulnerable-pkg',
          version: '1.0.0',
          vulnerabilities: [{
            severity: 'high',
            advisory_ghsa_id: 'GHSA-1234',
            advisory_summary: 'Test vulnerability',
            advisory_url: 'https://github.com/advisories/GHSA-1234'
          }]
        },
        {
          manifest: 'pnpm-lock.yaml',
          name: 'vulnerable-pkg',
          version: '1.0.0',
          vulnerabilities: [{
            severity: 'high',
            advisory_ghsa_id: 'GHSA-1234',
            advisory_summary: 'Test vulnerability',
            advisory_url: 'https://github.com/advisories/GHSA-1234'
          }]
        }
      ],
      summary: {
        ...createMockResults().summary,
        vulnerabilities: 1,
        highVulns: 1
      }
    })
    
    const output = formatter.format(results, mockComparison)

    const vulnMatches = output.match(/GHSA-1234/g)
    assert(vulnMatches && vulnMatches.length === 1, 'Should deduplicate identical vulnerabilities')
    
    assert(output.includes('🟠 vulnerable-pkg@1.0.0'))
    assert(output.includes('1 vulnerability'))
    assert(output.includes('**HIGH**: Test vulnerability'))
  })

  it('should handle multiple vulnerabilities in same package', () => {
    const formatter = new OutputFormatter('summary')
    const results = createMockResults({
      hasIssues: true,
      vulnerableChanges: [{
        manifest: 'package.json',
        name: 'multi-vuln-pkg',
        version: '2.0.0',
        vulnerabilities: [
          {
            severity: 'critical',
            advisory_ghsa_id: 'GHSA-crit-1',
            advisory_summary: 'Critical issue 1',
            advisory_url: 'https://github.com/advisories/GHSA-crit-1'
          },
          {
            severity: 'high',
            advisory_ghsa_id: 'GHSA-high-1',
            advisory_summary: 'High severity issue',
            advisory_url: 'https://github.com/advisories/GHSA-high-1'
          }
        ]
      }],
      summary: {
        ...createMockResults().summary,
        vulnerabilities: 2,
        criticalVulns: 1,
        highVulns: 1
      }
    })
    
    const output = formatter.format(results, mockComparison)

    assert(output.includes('🔴 multi-vuln-pkg@2.0.0'))
    assert(output.includes('2 vulnerabilities'))
    assert(output.includes('**CRITICAL**: Critical issue 1'))
    assert(output.includes('**HIGH**: High severity issue'))
    assert(output.includes('GHSA-crit-1'))
    assert(output.includes('GHSA-high-1'))
  })
})