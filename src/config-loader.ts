import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import YAML from 'yaml'

import type { Config, CliOptions } from './types.js'

export class ConfigLoader {
  private defaultConfig: Config = {
    failOnSeverity: 'low',
    failOnScopes: ['runtime'],
    denyLicenses: [
      'GPL-2.0',
      'GPL-3.0', 
      'AGPL-1.0',
      'AGPL-3.0',
      'LGPL-2.1',
      'LGPL-3.0',
      'CPAL-1.0',
      'OSL-3.0',
      'AFL-3.0',
      'EUPL-1.1',
      'EUPL-1.2',
      'CC-BY-SA-4.0',
      'SSPL-1.0',
      'BUSL-1.1',
      'JSON',
      'WTFPL',
      'MS-RL',
      'MS-PL',
      'CPOL-1.02',
      'RPL-1.1',
      'RPL-1.5',
      'QPL-1.0',
      'NPL-1.0',
      'NPL-1.1',
      'SPL-1.0',
      'IPL-1.0',
      'EPL-1.0',
      'EPL-2.0',
      'MPL-1.0',
      'MPL-1.1',
      'MPL-2.0',
      'CDDL-1.0',
      'CDDL-1.1',
      'CPL-1.0'
    ],
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
    if (config.allowLicenses && config.allowLicenses.length > 0 && 
        config.denyLicenses && config.denyLicenses.length > 0) {
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
