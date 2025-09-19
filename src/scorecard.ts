import type { DependencyChange, ScorecardData, ScorecardEntry } from './types.js'

export async function getScorecardLevels(
  changes: DependencyChange[]
): Promise<ScorecardData> {
  const dependencies: ScorecardEntry[] = []
  
  for (const change of changes) {
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

    let scorecard: any | null = null
    if (repositoryUrl) {
      try {
        scorecard = await getScorecard(repositoryUrl)
      } catch (error) {
        console.debug(`Error querying scorecard: ${error instanceof Error ? error.message : String(error)}`)
      }
    }

    dependencies.push({
      change,
      scorecard
    })
  }

  return { dependencies }
}

async function getScorecard(repositoryUrl: string): Promise<any> {
  const apiRoot = 'https://api.securityscorecards.dev'
  const url = `${apiRoot}/projects/${repositoryUrl}`
  
  const response = await fetch(url)
  if (response.ok) {
    return await response.json()
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
      const data = await response.json() as any
      if (data.relatedProjects && data.relatedProjects.length > 0) {
        return data.relatedProjects[0].projectKey.id
      }
    }
  } catch (error) {
    console.debug(`Error getting project URL from deps.dev: ${error}`)
  }
  
  return ''
}
