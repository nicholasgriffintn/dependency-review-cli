import { describe, it, mock } from 'node:test'
import assert from 'node:assert'

import { ScorecardService } from '../src/scorecard.js'

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

      const scorecardService = new ScorecardService()
      const result = await scorecardService.getScorecardLevels(changes)

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

      const scorecardService = new ScorecardService()
      const result = await scorecardService.getScorecardLevels(changes)

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

      const scorecardService = new ScorecardService()
      const result = await scorecardService.getScorecardLevels(changes)

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

      const scorecardService = new ScorecardService()
      const result = await scorecardService.getScorecardLevels(changes)

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

      const scorecardService = new ScorecardService()
      const result = await scorecardService.getScorecardLevels(changes)

      assert.strictEqual(result.dependencies.length, 2)
      assert.strictEqual(result.dependencies[0].change.name, 'added-pkg')
      assert.strictEqual(result.dependencies[0].scorecard.score, 5.0)
      assert.strictEqual(result.dependencies[1].change.name, 'removed-pkg')
      assert.strictEqual(result.dependencies[1].scorecard, null)
    } finally {
      restoreFetch()
    }
  })

  it('should cache scorecard results for repeated requests', async () => {
    const mockScorecardResponse = { score: 7.5 }
    let fetchCallCount = 0

    globalThis.fetch = mock.fn(async (url) => {
      if (url.includes('api.securityscorecards.dev')) {
        fetchCallCount++
        return {
          ok: true,
          json: async () => mockScorecardResponse
        }
      }
      return { ok: false, status: 404 }
    })

    try {
      const changes = [
        {
          change_type: 'added',
          ecosystem: 'npm',
          name: 'cached-pkg',
          version: '1.0.0',
          source_repository_url: 'https://github.com/test/cached-pkg',
          vulnerabilities: []
        },
        {
          change_type: 'added',
          ecosystem: 'npm',
          name: 'cached-pkg-2',
          version: '2.0.0',
          source_repository_url: 'https://github.com/test/cached-pkg',
          vulnerabilities: []
        }
      ]

      const scorecardService = new ScorecardService()
      const result = await scorecardService.getScorecardLevels(changes)

      assert.strictEqual(result.dependencies.length, 2)
      assert.strictEqual(fetchCallCount, 1, 'Should only make one API call due to caching')
      assert.strictEqual(result.dependencies[0].scorecard.score, 7.5)
      assert.strictEqual(result.dependencies[1].scorecard.score, 7.5)
    } finally {
      restoreFetch()
    }
  })

  it('should handle concurrent requests efficiently', async () => {
    const mockScorecardResponse = { score: 8.0 }
    let fetchCallCount = 0
    const startTime = Date.now()

    globalThis.fetch = mock.fn(async (url) => {
      if (url.includes('api.securityscorecards.dev')) {
        fetchCallCount++
        await new Promise(resolve => setTimeout(resolve, 100))
        return {
          ok: true,
          json: async () => mockScorecardResponse
        }
      }
      return { ok: false, status: 404 }
    })

    try {
      const changes = Array.from({ length: 10 }, (_, i) => ({
        change_type: 'added',
        ecosystem: 'npm',
        name: `concurrent-pkg-${i}`,
        version: '1.0.0',
        source_repository_url: `https://github.com/test/concurrent-pkg-${i}`,
        vulnerabilities: []
      }))

      const scorecardService = new ScorecardService()
      const result = await scorecardService.getScorecardLevels(changes)

      const endTime = Date.now()

      assert.strictEqual(result.dependencies.length, 10)
      assert.strictEqual(fetchCallCount, 10, 'Should make 10 API calls for 10 different repositories')
      assert(endTime - startTime < 500, 'Should complete in under 500ms due to concurrency (would take 1000ms sequentially)')
    } finally {
      restoreFetch()
    }
  })
})
