import { describe, it, mock } from 'node:test'
import assert from 'node:assert'

import { getScorecardLevels } from '../src/scorecard.js'

const originalFetch = globalThis.fetch
function mockFetch(url, response) {
  globalThis.fetch = mock.fn(async (requestUrl) => {
    if (requestUrl === url) {
      return {
        ok: true,
        json: async () => response
      }
    }
    return {
      ok: false,
      status: 404
    }
  })
}

function restoreFetch() {
  globalThis.fetch = originalFetch
}

describe('Scorecard', () => {
  it('should get scorecard data for GitHub repositories', async () => {
    const mockScorecardResponse = {
      date: '2023-01-01',
      repo: {
        name: 'github.com/test/test-package',
        commit: 'abc123'
      },
      score: 7.5,
      checks: []
    }

    mockFetch('https://api.securityscorecards.dev/projects/github.com/test/test-package', mockScorecardResponse)

    try {
      const changes = [{
        change_type: 'added',
        ecosystem: 'npm',
        name: 'test-package',
        version: '1.0.0',
        source_repository_url: 'https://github.com/test/test-package',
        vulnerabilities: []
      }]

      const result = await getScorecardLevels(changes)

      assert.strictEqual(result.dependencies.length, 1)
      assert.strictEqual(result.dependencies[0].change.name, 'test-package')
      assert.strictEqual(result.dependencies[0].scorecard.score, 7.5)
    } finally {
      restoreFetch()
    }
  })

  it('should handle GitHub Actions packages', async () => {
    const mockScorecardResponse = {
      date: '2023-01-01',
      score: 8.2
    }

    mockFetch('https://api.securityscorecards.dev/projects/github.com/actions/checkout', mockScorecardResponse)

    try {
      const changes = [{
        change_type: 'added',
        ecosystem: 'actions',
        name: 'actions/checkout/v4',
        version: 'v4',
        source_repository_url: null,
        vulnerabilities: []
      }]

      const result = await getScorecardLevels(changes)

      assert.strictEqual(result.dependencies.length, 1)
      assert.strictEqual(result.dependencies[0].scorecard.score, 8.2)
    } finally {
      restoreFetch()
    }
  })

  it('should fallback to deps.dev for missing repository URLs', async () => {
    const mockDepsDevResponse = {
      relatedProjects: [{
        projectKey: {
          id: 'github.com/example/package'
        }
      }]
    }

    const mockScorecardResponse = {
      date: '2023-01-01',
      score: 6.1
    }

    globalThis.fetch = mock.fn(async (url) => {
      if (url.includes('api.deps.dev')) {
        return {
          ok: true,
          json: async () => mockDepsDevResponse
        }
      } else if (url.includes('api.securityscorecards.dev')) {
        return {
          ok: true,
          json: async () => mockScorecardResponse
        }
      }
      return { ok: false, status: 404 }
    })

    try {
      const changes = [{
        change_type: 'added',
        ecosystem: 'npm',
        name: 'mystery-package',
        version: '2.0.0',
        source_repository_url: null,
        vulnerabilities: []
      }]

      const result = await getScorecardLevels(changes)

      assert.strictEqual(result.dependencies.length, 1)
      assert.strictEqual(result.dependencies[0].scorecard.score, 6.1)
    } finally {
      restoreFetch()
    }
  })

  it('should handle scorecard API failures gracefully', async () => {
    globalThis.fetch = mock.fn(async () => ({
      ok: false,
      status: 500
    }))

    try {
      const changes = [{
        change_type: 'added',
        ecosystem: 'npm',
        name: 'failing-package',
        version: '1.0.0',
        source_repository_url: 'https://github.com/test/failing-package',
        vulnerabilities: []
      }]

      const result = await getScorecardLevels(changes)

      assert.strictEqual(result.dependencies.length, 1)
      assert.strictEqual(result.dependencies[0].scorecard, null)
    } finally {
      restoreFetch()
    }
  })

  it('should process only added dependencies', async () => {
    mockFetch('https://api.securityscorecards.dev/projects/github.com/test/added-pkg', { score: 5.0 })

    try {
      const changes = [
        {
          change_type: 'added',
          ecosystem: 'npm',
          name: 'added-pkg',
          version: '1.0.0',
          source_repository_url: 'https://github.com/test/added-pkg',
          vulnerabilities: []
        },
        {
          change_type: 'removed',
          ecosystem: 'npm',
          name: 'removed-pkg',
          version: '1.0.0',
          source_repository_url: 'https://github.com/test/removed-pkg',
          vulnerabilities: []
        }
      ]

      const result = await getScorecardLevels(changes)

      assert.strictEqual(result.dependencies.length, 2)
      assert.strictEqual(result.dependencies[0].change.name, 'added-pkg')
      assert.strictEqual(result.dependencies[0].scorecard.score, 5.0)
      assert.strictEqual(result.dependencies[1].change.name, 'removed-pkg')
      assert.strictEqual(result.dependencies[1].scorecard, null)
    } finally {
      restoreFetch()
    }
  })
})
