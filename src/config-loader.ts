import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import YAML from "yaml";

import type { Config, CliOptions } from "./types.js";

/**
 * A class that loads the configuration for the CLI
 */
export class ConfigLoader {
	private defaultConfig: Config = {
		failOnSeverity: "low",
		failOnScopes: ["runtime"],
		licenses: {
			deny: [
				"GPL-2.0",
				"GPL-3.0",
				"AGPL-1.0",
				"AGPL-3.0",
				"LGPL-2.1",
				"LGPL-3.0",
				"CPAL-1.0",
				"OSL-3.0",
				"AFL-3.0",
				"EUPL-1.1",
				"EUPL-1.2",
				"CC-BY-SA-4.0",
				"SSPL-1.0",
				"BUSL-1.1",
				"JSON",
				"WTFPL",
				"MS-RL",
				"MS-PL",
				"CPOL-1.02",
				"RPL-1.1",
				"RPL-1.5",
				"QPL-1.0",
				"NPL-1.0",
				"NPL-1.1",
				"SPL-1.0",
				"IPL-1.0",
				"EPL-1.0",
				"EPL-2.0",
				"MPL-1.0",
				"MPL-1.1",
				"MPL-2.0",
				"CDDL-1.0",
				"CDDL-1.1",
				"CPL-1.0",
			],
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
		showOpenSSFScorecard: true,
		warnOnOpenSSFScorecardLevel: 3,
	};

	/**
	 * Load the configuration, either from the config file or using just the CLI and default values
	 * @param options - The options that were passed to the CLI
	 * @returns The configuration
	 */
	async load(options: CliOptions): Promise<Config> {
		let fileConfig: Partial<Config> = {};

		if (options.config) {
			fileConfig = await this.loadConfigFile(options.config);
		}

		const config: Config = {
			...this.defaultConfig,
			...fileConfig,
			...(options.failOnSeverity && { failOnSeverity: options.failOnSeverity }),
			...(options.warnOnly && { warnOnly: options.warnOnly }),
		};

		this.validateConfig(config);
		return config;
	}

	/**
	 * Load the configuration from the config file
	 * @param configPath - The path to the config file
	 * @returns The configuration
	 */
	private async loadConfigFile(configPath: string): Promise<Partial<Config>> {
		try {
			const fullPath = resolve(configPath);
			const content = readFileSync(fullPath, "utf-8");

			const data = YAML.parse(content);

			return this.convertConfigKeys(data) as Partial<Config>;
		} catch (error) {
			throw new Error(
				`Failed to load config file: ${error instanceof Error ? error.message : String(error)}`,
			);
		}
	}

	/**
	 * Check if the object is a valid configuration object
	 * @param obj - The object to check
	 * @returns True if the object is a valid configuration object
	 */
	private isConfigObject(obj: unknown): obj is Partial<Config> {
		return obj !== null && typeof obj === "object" && !Array.isArray(obj);
	}

	/**
	 * Convert the keys of the configuration object to camelCase
	 * @param obj - The object to convert
	 * @returns The converted object
	 */
	private convertConfigKeys(obj: unknown): Record<string, unknown> {
		if (!this.isConfigObject(obj)) {
			return {};
		}

		const result: Record<string, unknown> = {};

		for (const [key, value] of Object.entries(obj)) {
			const camelKey = key.replace(/-([a-z])/g, (_, letter) =>
				letter.toUpperCase(),
			);

			if (value && typeof value === "object" && !Array.isArray(value)) {
				result[camelKey] = this.convertConfigKeys(value);
			} else {
				result[camelKey] = value;
			}
		}

		return result;
	}

	/**
	 * Validate the configuration
	 * @param config - The configuration to validate
	 */
	private validateConfig(config: Config): void {
		const hasAllowLicenses =
			config.licenses?.allow && config.licenses.allow.length > 0;
		const hasDenyLicenses =
			config.licenses?.deny && config.licenses.deny.length > 0;

		if (hasAllowLicenses && hasDenyLicenses) {
			throw new Error("Cannot specify both allow and deny licenses");
		}

		if (!config.licenseCheck && !config.vulnerabilityCheck) {
			throw new Error(
				"Cannot disable both license checking and vulnerability checking",
			);
		}

		const validSeverities = ["low", "moderate", "high", "critical"];
		if (!validSeverities.includes(config.failOnSeverity)) {
			throw new Error(
				`Invalid fail-on-severity: ${config.failOnSeverity}. Must be one of: ${validSeverities.join(", ")}`,
			);
		}
	}
}
