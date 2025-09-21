import { describe, it, mock } from "node:test";
import assert from "node:assert";
import { GitHubClient } from "../src/github-client.js";

describe("GitHubClient", () => {
	it("should create client with environment token", () => {
		process.env.GITHUB_TOKEN = "test-token";
		const client = new GitHubClient();
		assert(client instanceof GitHubClient);
		delete process.env.GITHUB_TOKEN;
	});

	it("should handle 404 error for non-existent repository", async () => {
		const client = new GitHubClient("fake-token");

		client.octokit.rest.repos.get = mock.fn(async () => {
			const error = new Error("Not Found");
			error.status = 404;
			throw error;
		});

		await assert.rejects(
			client.getRepository("nonexistent", "repo"),
			/Repository nonexistent\/repo not found/,
		);

		assert.strictEqual(client.octokit.rest.repos.get.mock.callCount(), 1);
		const call = client.octokit.rest.repos.get.mock.calls[0];
		assert.deepStrictEqual(call.arguments[0], {
			owner: "nonexistent",
			repo: "repo",
		});
	});

	it("should handle 403 error for dependency graph API", async () => {
		const client = new GitHubClient("fake-token");

		client.octokit.request = mock.fn(async () => {
			const error = new Error("Forbidden");
			error.status = 403;
			throw error;
		});

		await assert.rejects(
			client.compareDependencies({
				owner: "test",
				repo: "test",
				baseRef: "main",
				headRef: "HEAD",
			}),
			/Dependency review is not supported/,
		);

		assert.strictEqual(client.octokit.request.mock.callCount(), 1);
		const call = client.octokit.request.mock.calls[0];
		assert.strictEqual(
			call.arguments[0],
			"GET /repos/{owner}/{repo}/dependency-graph/compare/{basehead}",
		);
		assert.deepStrictEqual(call.arguments[1], {
			owner: "test",
			repo: "test",
			basehead: "main...HEAD",
		});
	});

	it("should parse snapshot warnings from response headers", async () => {
		const client = new GitHubClient("fake-token");
		const mockWarnings =
			"Some dependencies may not have complete vulnerability data";
		const encodedWarnings = Buffer.from(mockWarnings, "utf-8").toString(
			"base64",
		);

		client.octokit.request = mock.fn(async () => ({
			data: [
				{
					change_type: "added",
					manifest: "package.json",
					ecosystem: "npm",
					name: "test-package",
					version: "1.0.0",
					package_url: "pkg:npm/test-package@1.0.0",
					license: "MIT",
					source_repository_url: null,
					vulnerabilities: [],
				},
			],
			headers: {
				"x-github-dependency-graph-snapshot-warnings": encodedWarnings,
			},
		}));

		const result = await client.compareDependencies({
			owner: "test",
			repo: "test",
			baseRef: "main",
			headRef: "HEAD",
		});

		assert.strictEqual(result.snapshot_warnings, mockWarnings);
		assert.strictEqual(result.changes.length, 1);
		assert.strictEqual(result.changes[0].name, "test-package");

		assert.strictEqual(client.octokit.request.mock.callCount(), 1);
	});

	it("should return repository data successfully", async () => {
		const client = new GitHubClient("fake-token");
		const mockRepo = {
			id: 12345,
			name: "test-repo",
			full_name: "test/test-repo",
			private: false,
		};

		client.octokit.rest.repos.get = mock.fn(async () => ({
			data: mockRepo,
		}));

		const result = await client.getRepository("test", "test-repo");

		assert.deepStrictEqual(result, mockRepo);
		assert.strictEqual(client.octokit.rest.repos.get.mock.callCount(), 1);
	});

	it("should handle empty dependency changes", async () => {
		const client = new GitHubClient("fake-token");

		client.octokit.request = mock.fn(async () => ({
			data: [],
			headers: {},
		}));

		const result = await client.compareDependencies({
			owner: "test",
			repo: "empty-repo",
			baseRef: "main",
			headRef: "HEAD",
		});

		assert.strictEqual(result.changes.length, 0);
		assert.strictEqual(result.snapshot_warnings, "");
	});
});
