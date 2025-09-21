import { describe, it } from "node:test";
import assert from "node:assert";

import { ReviewEngine } from "../src/review-engine.js";

const mockConfig = {
	failOnSeverity: "low",
	failOnScopes: ["runtime"],
	licenses: {
		allow: undefined,
		deny: undefined,
	},
	packages: {
		deny: [],
	},
	groups: {
		deny: [],
	},
	ghsas: {
		allow: [],
	},
	licenseCheckExclusions: undefined,
	licenseCheck: true,
	vulnerabilityCheck: true,
	warnOnly: false,
	showOpenSSFScorecard: false,
	warnOnOpenSSFScorecardLevel: 3,
};

const createMockChange = (overrides = {}) => ({
	change_type: "added",
	manifest: "package.json",
	ecosystem: "npm",
	name: "test-package",
	version: "1.0.0",
	package_url: "pkg:npm/test-package@1.0.0",
	license: "MIT",
	source_repository_url: "https://github.com/test/test-package",
	scope: "runtime",
	vulnerabilities: [],
	...overrides,
});

describe("ReviewEngine", () => {
	it("should analyze dependencies with no issues", async () => {
		const engine = new ReviewEngine(mockConfig);
		const comparison = {
			changes: [createMockChange()],
			snapshot_warnings: "",
		};

		const results = await engine.analyze(comparison);

		assert.strictEqual(results.hasIssues, false);
		assert.strictEqual(results.vulnerableChanges.length, 0);
		assert.strictEqual(results.summary.totalChanges, 1);
		assert.strictEqual(results.summary.added, 1);
		assert.strictEqual(results.summary.removed, 0);
	});

	it("should detect vulnerable dependencies", async () => {
		const vulnerableChange = createMockChange({
			vulnerabilities: [
				{
					severity: "high",
					advisory_ghsa_id: "GHSA-1234-5678-9012",
					advisory_summary: "Test vulnerability",
					advisory_url: "https://github.com/advisories/GHSA-1234-5678-9012",
				},
			],
		});

		const engine = new ReviewEngine(mockConfig);
		const comparison = {
			changes: [vulnerableChange],
			snapshot_warnings: "",
		};

		const results = await engine.analyze(comparison);

		assert.strictEqual(results.hasIssues, true);
		assert.strictEqual(results.vulnerableChanges.length, 1);
		assert.strictEqual(results.summary.vulnerabilities, 1);
		assert.strictEqual(results.summary.highVulns, 1);
	});

	it("should filter by severity threshold", async () => {
		const lowVulnChange = createMockChange({
			vulnerabilities: [
				{
					severity: "low",
					advisory_ghsa_id: "GHSA-low-1234",
					advisory_summary: "Low severity issue",
					advisory_url: "https://github.com/advisories/GHSA-low-1234",
				},
			],
		});

		const configHighSeverity = { ...mockConfig, failOnSeverity: "high" };
		const engine = new ReviewEngine(configHighSeverity);
		const comparison = {
			changes: [lowVulnChange],
			snapshot_warnings: "",
		};

		const results = await engine.analyze(comparison);

		assert.strictEqual(results.hasIssues, false);
		assert.strictEqual(results.vulnerableChanges.length, 0);
	});

	it("should detect forbidden licenses", async () => {
		const forbiddenLicenseChange = createMockChange({
			license: "GPL-3.0",
		});

		const configWithAllowList = {
			...mockConfig,
			licenses: {
				...mockConfig.licenses,
				allow: ["MIT", "Apache-2.0"],
			},
		};
		const engine = new ReviewEngine(configWithAllowList);
		const comparison = {
			changes: [forbiddenLicenseChange],
			snapshot_warnings: "",
		};

		const results = await engine.analyze(comparison);

		assert.strictEqual(results.hasIssues, true);
		assert.strictEqual(results.invalidLicenseChanges.forbidden.length, 1);
		assert.strictEqual(
			results.invalidLicenseChanges.forbidden[0].license,
			"GPL-3.0",
		);
	});

	it("should detect unlicensed packages", async () => {
		const unlicensedChange = createMockChange({
			license: null,
		});

		const engine = new ReviewEngine(mockConfig);
		const comparison = {
			changes: [unlicensedChange],
			snapshot_warnings: "",
		};

		const results = await engine.analyze(comparison);

		assert.strictEqual(results.invalidLicenseChanges.unlicensed.length, 1);
		assert.strictEqual(
			results.invalidLicenseChanges.unlicensed[0].name,
			"test-package",
		);
	});

	it("should detect denied packages", async () => {
		const deniedChange = createMockChange({
			package_url: "pkg:npm/banned-package@1.0.0",
			name: "banned-package",
		});

		const configWithDeniedPackages = {
			...mockConfig,
			packages: {
				...mockConfig.packages,
				deny: ["banned-package"],
			},
		};
		const engine = new ReviewEngine(configWithDeniedPackages);
		const comparison = {
			changes: [deniedChange],
			snapshot_warnings: "",
		};

		const results = await engine.analyze(comparison);

		assert.strictEqual(results.hasIssues, true);
		assert.strictEqual(results.deniedChanges.length, 1);
		assert.strictEqual(results.deniedChanges[0].name, "banned-package");
	});

	it("should skip checks when warn-only is enabled", async () => {
		const vulnerableChange = createMockChange({
			vulnerabilities: [
				{
					severity: "critical",
					advisory_ghsa_id: "GHSA-crit-1234",
					advisory_summary: "Critical vulnerability",
					advisory_url: "https://github.com/advisories/GHSA-crit-1234",
				},
			],
		});

		const warnOnlyConfig = { ...mockConfig, warnOnly: true };
		const engine = new ReviewEngine(warnOnlyConfig);
		const comparison = {
			changes: [vulnerableChange],
			snapshot_warnings: "",
		};

		const results = await engine.analyze(comparison);

		assert.strictEqual(results.hasIssues, false);
		assert.strictEqual(results.vulnerableChanges.length, 1);
	});

	it("should exclude packages from license checks", async () => {
		const excludedChange = createMockChange({
			package_url: "pkg:npm/excluded-package@1.0.0",
			license: "GPL-3.0",
		});

		const configWithExclusions = {
			...mockConfig,
			licenses: {
				...mockConfig.licenses,
				allow: ["MIT"],
			},
			licenseCheckExclusions: ["pkg:npm/excluded-package"],
		};
		const engine = new ReviewEngine(configWithExclusions);
		const comparison = {
			changes: [excludedChange],
			snapshot_warnings: "",
		};

		const results = await engine.analyze(comparison);

		assert.strictEqual(results.hasIssues, false);
		assert.strictEqual(results.invalidLicenseChanges.forbidden.length, 0);
	});
});
