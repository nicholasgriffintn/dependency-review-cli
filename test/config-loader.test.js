import { describe, it } from 'node:test'
import assert from 'node:assert'
import fs from 'node:fs'
import path from 'node:path'

import { ConfigLoader } from '../src/config-loader.js'

describe('ConfigLoader', () => {
  it('should load default configuration', async () => {
    const loader = new ConfigLoader()
    const config = await loader.load({
      owner: 'test',
      repo: 'test',
      baseRef: 'main',
      headRef: 'HEAD'
    })

    assert.strictEqual(config.failOnSeverity, 'low')
    assert.deepStrictEqual(config.failOnScopes, ['runtime'])
    assert.strictEqual(config.licenseCheck, true)
    assert.strictEqual(config.vulnerabilityCheck, true)
    assert.strictEqual(config.warnOnly, false)
  })

  it('should override config with CLI options', async () => {
    const loader = new ConfigLoader()
    const config = await loader.load({
      owner: 'test',
      repo: 'test', 
      baseRef: 'main',
      headRef: 'HEAD',
      failOnSeverity: 'high',
      warnOnly: true
    })

    assert.strictEqual(config.failOnSeverity, 'high')
    assert.strictEqual(config.warnOnly, true)
  })

  it('should validate mutually exclusive license options', async () => {
    const configContent = `
fail-on-severity: moderate
allow-licenses:
  - MIT
deny-licenses:
  - GPL-3.0
`
    const configPath = path.join(process.cwd(), 'test-config.yml')
    fs.writeFileSync(configPath, configContent)

    try {
      const loader = new ConfigLoader()
      await assert.rejects(
        loader.load({
          owner: 'test',
          repo: 'test',
          baseRef: 'main', 
          headRef: 'HEAD',
          config: configPath
        }),
        /Cannot specify both allow-licenses and deny-licenses/
      )
    } finally {
      fs.unlinkSync(configPath)
    }
  })

  it('should validate that at least one check is enabled', async () => {
    const configContent = `
license-check: false
vulnerability-check: false
`
    const configPath = path.join(process.cwd(), 'test-config-invalid.yml')
    fs.writeFileSync(configPath, configContent)

    try {
      const loader = new ConfigLoader()
      await assert.rejects(
        loader.load({
          owner: 'test',
          repo: 'test',
          baseRef: 'main',
          headRef: 'HEAD', 
          config: configPath
        }),
        /Cannot disable both license checking and vulnerability checking/
      )
    } finally {
      fs.unlinkSync(configPath)
    }
  })

  it('should load valid config file', async () => {
    const configContent = `
fail-on-severity: high
allow-licenses:
  - MIT
  - Apache-2.0
deny-packages:
  - pkg:npm/lodash@4.17.20
warn-only: true
`
    const configPath = path.join(process.cwd(), 'test-config-valid.yml')
    fs.writeFileSync(configPath, configContent)

    try {
      const loader = new ConfigLoader()
      const config = await loader.load({
        owner: 'test',
        repo: 'test',
        baseRef: 'main',
        headRef: 'HEAD',
        config: configPath
      })

      assert.strictEqual(config.failOnSeverity, 'high')
      assert.deepStrictEqual(config.allowLicenses, ['MIT', 'Apache-2.0'])
      assert.deepStrictEqual(config.denyPackages, ['pkg:npm/lodash@4.17.20'])
      assert.strictEqual(config.warnOnly, true)
    } finally {
      fs.unlinkSync(configPath)
    }
  })
})
