import { Octokit } from '@octokit/rest'
import { retry } from '@octokit/plugin-retry'

import type { ComparisonResponse, DependencyChange } from './types.js'

const RetryOctokit = Octokit.plugin(retry)

export class GitHubClient {
  private octokit: Octokit

  constructor(token?: string) {
    this.octokit = new RetryOctokit({
      auth: token || process.env.GITHUB_TOKEN,
      retry: {
        doNotRetry: ['400', '401', '403', '404', '422']
      }
    })
  }

  async compareDependencies({
    owner,
    repo,
    baseRef,
    headRef
  }: {
    owner: string
    repo: string
    baseRef: string
    headRef: string
  }): Promise<ComparisonResponse> {
    const snapshotWarningsHeader = 'x-github-dependency-graph-snapshot-warnings'
    let snapshot_warnings = ''

    try {
      const response = await this.octokit.request('GET /repos/{owner}/{repo}/dependency-graph/compare/{basehead}', {
        owner,
        repo,
        basehead: `${baseRef}...${headRef}`
      })

      if (response.headers[snapshotWarningsHeader]) {
        snapshot_warnings = Buffer.from(
          response.headers[snapshotWarningsHeader] as string,
          'base64'
        ).toString('utf-8')
      }

      return {
        changes: response.data as DependencyChange[],
        snapshot_warnings
      }
    } catch (error: any) {
      if (error.status === 404) {
        throw new Error(
          'Dependency review could not obtain dependency data for the specified repository or revision range. ' +
          'Make sure the repository exists and has dependency graph enabled.'
        )
      } else if (error.status === 403) {
        throw new Error(
          'Dependency review is not supported on this repository. ' +
          'Please ensure that dependency graph is enabled along with GitHub Advanced Security on private repositories.'
        )
      }
      throw error
    }
  }

  async getRepository(owner: string, repo: string) {
    try {
      const { data } = await this.octokit.rest.repos.get({
        owner,
        repo
      })
      return data
    } catch (error: any) {
      if (error.status === 404) {
        throw new Error(`Repository ${owner}/${repo} not found`)
      }
      throw error
    }
  }
}
