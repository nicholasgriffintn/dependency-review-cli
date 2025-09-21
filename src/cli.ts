#!/usr/bin/env node

import { Command } from "commander";

import { GitHubClient } from "./github-client.js";
import { ReviewEngine } from "./review-engine.js";
import { OutputFormatter } from "./output-formatter.js";
import { ConfigLoader } from "./config-loader.js";
import { PrCommenter } from "./pr-comment.js";
import { logger } from "./utils/logger.js";
import type { CliOptions, ReviewResults } from "./types.js";

const program = new Command();

program
	.name("dependency-review")
	.description(
		"Review dependency changes and vulnerabilities using the GitHub API",
	)
	.version("1.0.0");

program
	.argument("<owner>", "Repository owner")
	.argument("<repo>", "Repository name")
	.argument("<base-ref>", "Base git reference (commit SHA, branch, or tag)")
	.argument("<head-ref>", "Head git reference (commit SHA, branch, or tag)")
	.option("-c, --config <path>", "Path to configuration file")
	.option(
		"-o, --output <format>",
		"Output format (json, table, markdown, summary)",
		"summary",
	)
	.option(
		"--fail-on-severity <severity>",
		"Fail on vulnerability severity (low, moderate, high, critical)",
		"low",
	)
	.option("--warn-only", "Only warn, never fail the command")
	.option("--no-license-check", "Disable license checking")
	.option("--no-vulnerability-check", "Disable vulnerability checking")
	.option("--quiet", "Suppress log messages, only show output")
	.option(
		"--comment-summary-in-pr <mode>",
		"Comment summary in PR (always, on-failure, never)",
		"never",
	)
	.option("--pr-number <number>", "Pull request number for commenting")
	.action(async (owner, repo, baseRef, headRef, options) => {
		try {
			const cliOptions: CliOptions = {
				owner,
				repo,
				baseRef,
				headRef,
				config: options.config,
				output: options.output,
				failOnSeverity: options.failOnSeverity,
				warnOnly: options.warnOnly,
				quiet: options.quiet,
				commentSummaryInPr: options.commentSummaryInPr,
				prNumber: options.prNumber ? Number.parseInt(options.prNumber) : undefined,
			};

			logger(cliOptions, "Initializing dependency review config...");
			const configLoader = new ConfigLoader();
			const config = await configLoader.load(cliOptions);

			logger(cliOptions, "Connecting to GitHub...");
			const githubClient = new GitHubClient();
			await githubClient.getRepository(owner, repo);

			logger(cliOptions, "Comparing dependency changes...");
			const comparison = await githubClient.compareDependencies({
				owner,
				repo,
				baseRef,
				headRef,
			});

			let results: ReviewResults;
			const hasChanges = comparison.changes && comparison.changes.length > 0;

			if (hasChanges) {
				logger(cliOptions, "Analyzing dependencies...");
				const reviewEngine = new ReviewEngine(config);
				results = await reviewEngine.analyze(comparison);
			} else {
				logger(cliOptions, "✅ No dependency changes found.");

				results = {
					vulnerableChanges: [],
					invalidLicenseChanges: {
						forbidden: [],
						unresolved: [],
						unlicensed: [],
					},
					deniedChanges: [],
					scorecard: null,
					hasIssues: false,
					summary: {
						totalChanges: 0,
						added: 0,
						removed: 0,
						vulnerabilities: 0,
						criticalVulns: 0,
						highVulns: 0,
						moderateVulns: 0,
						lowVulns: 0,
					},
				};
			}

			const formatter = new OutputFormatter(cliOptions.output || "summary");
			const output = formatter.format(results, comparison);

			console.log(output);

			if (
				cliOptions.commentSummaryInPr &&
				cliOptions.commentSummaryInPr !== "never" &&
				cliOptions.prNumber
			) {
				logger(cliOptions, "Adding comment to PR...");
				const commenter = new PrCommenter();
				await commenter.commentOnPr(
					{
						owner,
						repo,
						pullNumber: cliOptions.prNumber,
						mode: cliOptions.commentSummaryInPr as
							| "always"
							| "on-failure"
							| "never",
					},
					results,
					comparison,
				);
				logger(cliOptions, "✅ PR comment updated");
			}

			if (results.hasIssues && !config.warnOnly) {
				process.exit(1);
			}
		} catch (error) {
			console.error(
				`❌ Error: ${error instanceof Error ? error.message : String(error)}`,
			);
			process.exit(1);
		}
	});

program.parse();
