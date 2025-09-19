import type { DependencyChange, ScorecardData, ScorecardEntry, ScorecardResponse } from './types.js'

export class ScorecardService {
  private readonly concurrency = 5
  private cache = new Map<string, ScorecardResponse>()
  private pendingRequests = new Map<string, Promise<ScorecardResponse | null>>()
  
  async getScorecardLevels(changes: DependencyChange[]): Promise<ScorecardData> {
    const chunks = this.chunkArray(changes, this.concurrency)
    const results = await Promise.all(
      chunks.map(chunk => this.processChunk(chunk))
    )
    return { dependencies: results.flat() }
  }
  
  private async processChunk(changes: DependencyChange[]): Promise<ScorecardEntry[]> {
    return Promise.all(changes.map(change => this.getScorecardWithCache(change)))
  }

  private async getScorecardWithCache(change: DependencyChange): Promise<ScorecardEntry> {
    const ecosystem = change.ecosystem
    const packageName = change.name
    const version = change.version

    let repositoryUrl = change.source_repository_url
    
    if (repositoryUrl?.startsWith('https://')) {
      repositoryUrl = repositoryUrl.replace('https://', '')
    }

    if (ecosystem === 'actions') {
      const parts = packageName.split('/')
      repositoryUrl = `github.com/${parts[0]}/${parts[1]}`
    }

    if (!repositoryUrl) {
      repositoryUrl = await getProjectUrl(ecosystem, packageName, version)
    }

    let scorecard: ScorecardResponse | null = null
    if (repositoryUrl) {
      const cacheKey = `scorecard:${repositoryUrl}`
      
      if (this.cache.has(cacheKey)) {
        scorecard = this.cache.get(cacheKey) || null
      } else if (this.pendingRequests.has(cacheKey)) {
        scorecard = await this.pendingRequests.get(cacheKey) || null
      } else {
        const requestPromise = this.fetchScorecard(repositoryUrl)
        this.pendingRequests.set(cacheKey, requestPromise)
        
        try {
          scorecard = await requestPromise
          if (scorecard) {
            this.cache.set(cacheKey, scorecard)
          }
        } finally {
          this.pendingRequests.delete(cacheKey)
        }
      }
    }

    return {
      change,
      scorecard
    }
  }

  private async fetchScorecard(repositoryUrl: string): Promise<ScorecardResponse | null> {
    try {
      return await getScorecard(repositoryUrl)
    } catch (error) {
      console.debug(`Error querying scorecard: ${error instanceof Error ? error.message : String(error)}`)
      return null
    }
  }

  private chunkArray<T>(array: T[], chunkSize: number): T[][] {
    const chunks: T[][] = []
    for (let i = 0; i < array.length; i += chunkSize) {
      chunks.push(array.slice(i, i + chunkSize))
    }
    return chunks
  }
}

async function getScorecard(repositoryUrl: string): Promise<ScorecardResponse | null> {
  const apiRoot = 'https://api.securityscorecards.dev'
  const url = `${apiRoot}/projects/${repositoryUrl}`
  
  const response = await fetch(url)
  if (response.ok) {
    return await response.json() as ScorecardResponse
  } else {
    console.debug(`Couldn't get scorecard data for ${repositoryUrl}`)
    return null
  }
}

async function getProjectUrl(
  ecosystem: string,
  packageName: string,
  version: string
): Promise<string> {
  console.debug(`Getting deps.dev data for ${packageName} ${version}`)
  
  const depsDevAPIRoot = 'https://api.deps.dev'
  const url = `${depsDevAPIRoot}/v3/systems/${ecosystem}/packages/${packageName}/versions/${version}`
  
  try {
    const response = await fetch(url)
    if (response.ok) {
      const data = await response.json() as { relatedProjects: { projectKey: { id: string } }[] }
      if (data.relatedProjects && data.relatedProjects.length > 0) {
        return data.relatedProjects[0].projectKey.id
      }
    }
  } catch (error) {
    console.debug(`Error getting project URL from deps.dev: ${error}`)
  }
  
  return ''
}
