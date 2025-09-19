import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import YAML from 'yaml'

import type { Config, CliOptions } from './types.js'

export class ConfigLoader {
  private defaultConfig: Config = {
    failOnSeverity: 'low',
    failOnScopes: ['runtime'],
    allowGhsas: [],
    denyPackages: [],
    denyGroups: [],
    licenseCheck: true,
    vulnerabilityCheck: true,
    warnOnly: false,
    showOpenSSFScorecard: true,
    warnOnOpenSSFScorecardLevel: 3
  }

  async load(options: CliOptions): Promise<Config> {
    let fileConfig: Partial<Config> = {}

    if (options.config) {
      fileConfig = await this.loadConfigFile(options.config)
    }

    const config: Config = {
      ...this.defaultConfig,
      ...fileConfig,
      ...(options.failOnSeverity && { failOnSeverity: options.failOnSeverity }),
      ...(options.warnOnly && { warnOnly: options.warnOnly })
    }

    this.validateConfig(config)
    return config
  }

  private async loadConfigFile(configPath: string): Promise<Partial<Config>> {
    try {
      const fullPath = resolve(configPath)
      const content = readFileSync(fullPath, 'utf-8')
      
      const data = YAML.parse(content)
      
      const converted: Record<string, unknown> = {}
      for (const [key, value] of Object.entries(data)) {
        const camelKey = key.replace(/-([a-z])/g, (_, letter) => letter.toUpperCase())
        converted[camelKey] = value
      }

      return converted
    } catch (error) {
      throw new Error(`Failed to load config file: ${error instanceof Error ? error.message : String(error)}`)
    }
  }

  private validateConfig(config: Config): void {
    if (config.allowLicenses && config.denyLicenses) {
      throw new Error('Cannot specify both allow-licenses and deny-licenses')
    }

    if (!config.licenseCheck && !config.vulnerabilityCheck) {
      throw new Error('Cannot disable both license checking and vulnerability checking')
    }

    const validSeverities = ['low', 'moderate', 'high', 'critical']
    if (!validSeverities.includes(config.failOnSeverity)) {
      throw new Error(`Invalid fail-on-severity: ${config.failOnSeverity}. Must be one of: ${validSeverities.join(', ')}`)
    }
  }
}
