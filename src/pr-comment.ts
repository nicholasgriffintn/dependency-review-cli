import { Octokit } from '@octokit/rest'

import type { ReviewResults } from './review-engine.js'
import type { ComparisonResponse } from './types.js'
import { OutputFormatter } from './output-formatter.js'

export interface PrCommentOptions {
  owner: string
  repo: string
  pullNumber: number
  mode: 'always' | 'on-failure' | 'never'
}

export class PrCommenter {
  private octokit: Octokit
  private commentMarker = '<!-- dependency-review-cli -->'

  constructor(token?: string) {
    this.octokit = new Octokit({
      auth: token || process.env.GITHUB_TOKEN
    })
  }

  async commentOnPr(
    options: PrCommentOptions,
    results: ReviewResults,
    comparison: ComparisonResponse
  ): Promise<void> {
    if (options.mode === 'never') {
      return
    }

    if (options.mode === 'on-failure' && !results.hasIssues) {
      return
    }

    const formatter = new OutputFormatter('summary')
    const content = formatter.format(results, comparison)
    
    const commentBody = `${this.commentMarker}\n${content}`

    try {
      const { data: comments } = await this.octokit.rest.issues.listComments({
        owner: options.owner,
        repo: options.repo,
        issue_number: options.pullNumber
      })

      const existingComment = comments.find(comment => 
        comment.body?.includes(this.commentMarker)
      )

      if (existingComment) {
        await this.octokit.rest.issues.updateComment({
          owner: options.owner,
          repo: options.repo,
          comment_id: existingComment.id,
          body: commentBody
        })
      } else {
        await this.octokit.rest.issues.createComment({
          owner: options.owner,
          repo: options.repo,
          issue_number: options.pullNumber,
          body: commentBody
        })
      }
    } catch (error: any) {
      throw new Error(`Failed to comment on PR: ${error.message}`)
    }
  }

  async deletePrComment(options: Omit<PrCommentOptions, 'mode'>): Promise<void> {
    try {
      const { data: comments } = await this.octokit.rest.issues.listComments({
        owner: options.owner,
        repo: options.repo,
        issue_number: options.pullNumber
      })

      const existingComment = comments.find(comment => 
        comment.body?.includes(this.commentMarker)
      )

      if (existingComment) {
        await this.octokit.rest.issues.deleteComment({
          owner: options.owner,
          repo: options.repo,
          comment_id: existingComment.id
        })
      }
    } catch (error: any) {
      console.warn(`Failed to delete PR comment: ${error.message}`)
    }
  }
}
