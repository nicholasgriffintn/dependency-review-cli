import { describe, it, mock } from 'node:test'
import assert from 'node:assert'
import { PrCommenter } from '../src/pr-comment.js'

const mockResults = {
  vulnerableChanges: [],
  invalidLicenseChanges: { forbidden: [], unresolved: [], unlicensed: [] },
  deniedChanges: [],
  scorecard: null,
  hasIssues: false,
  summary: {
    totalChanges: 3,
    added: 2,
    removed: 1,
    vulnerabilities: 0,
    criticalVulns: 0,
    highVulns: 0,
    moderateVulns: 0,
    lowVulns: 0
  }
}

const mockResultsWithIssues = {
  ...mockResults,
  hasIssues: true,
  vulnerableChanges: [{
    change_type: 'added',
    name: 'vulnerable-pkg',
    version: '1.0.0',
    vulnerabilities: [{
      severity: 'high',
      advisory_ghsa_id: 'GHSA-1234',
      advisory_summary: 'Test vulnerability',
      advisory_url: 'https://github.com/advisories/GHSA-1234'
    }]
  }]
}

const mockComparison = {
  changes: [],
  snapshot_warnings: ''
}

describe('PrCommenter', () => {
  it('should skip commenting when mode is never', async () => {
    const commenter = new PrCommenter('fake-token')
    
    commenter.octokit.rest.issues.listComments = mock.fn(async () => ({ data: [] }))
    
    await commenter.commentOnPr(
      { owner: 'test', repo: 'repo', pullNumber: 1, mode: 'never' },
      mockResults,
      mockComparison
    )
    
    assert.strictEqual(commenter.octokit.rest.issues.listComments.mock.callCount(), 0, 'Should not call GitHub API')
  })

  it('should skip commenting when mode is on-failure and no issues', async () => {
    const commenter = new PrCommenter('fake-token')
    commenter.octokit.rest.issues.listComments = mock.fn(async () => ({ data: [] }))
    
    await commenter.commentOnPr(
      { owner: 'test', repo: 'repo', pullNumber: 1, mode: 'on-failure' },
      mockResults,
      mockComparison
    )
    
    assert.strictEqual(commenter.octokit.rest.issues.listComments.mock.callCount(), 0, 'Should not call GitHub API')
  })

  it('should create comment when mode is always', async () => {
    const commenter = new PrCommenter('fake-token')
    
    commenter.octokit.rest.issues.listComments = mock.fn(async () => ({ data: [] }))
    commenter.octokit.rest.issues.createComment = mock.fn(async () => ({ data: { id: 123 } }))
    
    await commenter.commentOnPr(
      { owner: 'testowner', repo: 'testrepo', pullNumber: 42, mode: 'always' },
      mockResults,
      mockComparison
    )
    
    assert.strictEqual(commenter.octokit.rest.issues.listComments.mock.callCount(), 1, 'Should check for existing comments')
    assert.strictEqual(commenter.octokit.rest.issues.createComment.mock.callCount(), 1, 'Should create new comment')
    
    const createCall = commenter.octokit.rest.issues.createComment.mock.calls[0]
    assert.strictEqual(createCall.arguments[0].owner, 'testowner')
    assert.strictEqual(createCall.arguments[0].repo, 'testrepo')
    assert.strictEqual(createCall.arguments[0].issue_number, 42)
    assert.ok(createCall.arguments[0].body.includes('dependency-review-cli'))
    assert.ok(createCall.arguments[0].body.includes('Total changes: 3'))
  })

  it('should update existing comment', async () => {
    const commenter = new PrCommenter('fake-token')
    
    const existingComment = {
      id: 456,
      body: '<!-- dependency-review-cli -->\nOld content'
    }
    
    commenter.octokit.rest.issues.listComments = mock.fn(async () => ({ data: [existingComment] }))
    commenter.octokit.rest.issues.updateComment = mock.fn(async () => ({ data: { id: 456 } }))
    commenter.octokit.rest.issues.createComment = mock.fn(async () => ({ data: { id: 123 } }))
    
    await commenter.commentOnPr(
      { owner: 'test', repo: 'repo', pullNumber: 1, mode: 'always' },
      mockResults,
      mockComparison
    )
    
    assert.strictEqual(commenter.octokit.rest.issues.updateComment.mock.callCount(), 1, 'Should update existing comment')
    assert.strictEqual(commenter.octokit.rest.issues.createComment.mock.callCount(), 0, 'Should not create new comment')
    
    const updateCall = commenter.octokit.rest.issues.updateComment.mock.calls[0]
    assert.strictEqual(updateCall.arguments[0].comment_id, 456)
  })

  it('should comment on failure when has issues', async () => {
    const commenter = new PrCommenter('fake-token')
    
    commenter.octokit.rest.issues.listComments = mock.fn(async () => ({ data: [] }))
    commenter.octokit.rest.issues.createComment = mock.fn(async () => ({ data: { id: 123 } }))
    
    await commenter.commentOnPr(
      { owner: 'test', repo: 'repo', pullNumber: 1, mode: 'on-failure' },
      mockResultsWithIssues,
      mockComparison
    )
    
    assert.strictEqual(commenter.octokit.rest.issues.createComment.mock.callCount(), 1, 'Should create comment when has issues')
    
    const createCall = commenter.octokit.rest.issues.createComment.mock.calls[0]
    assert.ok(createCall.arguments[0].body.includes('vulnerable-pkg'))
  })

  it('should delete existing comment', async () => {
    const commenter = new PrCommenter('fake-token')
    
    const existingComment = {
      id: 789,
      body: '<!-- dependency-review-cli -->\nComment to delete'
    }
    
    commenter.octokit.rest.issues.listComments = mock.fn(async () => ({ data: [existingComment] }))
    commenter.octokit.rest.issues.deleteComment = mock.fn(async () => ({ data: {} }))
    
    await commenter.deletePrComment({
      owner: 'test',
      repo: 'repo',
      pullNumber: 1
    })
    
    assert.strictEqual(commenter.octokit.rest.issues.deleteComment.mock.callCount(), 1, 'Should delete comment')
    
    const deleteCall = commenter.octokit.rest.issues.deleteComment.mock.calls[0]
    assert.strictEqual(deleteCall.arguments[0].comment_id, 789)
  })
})