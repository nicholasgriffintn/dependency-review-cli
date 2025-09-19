import { describe, it } from 'node:test'
import assert from 'node:assert'
import { spawn } from 'node:child_process'
import path from 'node:path'

describe('Integration Tests', () => {
  it('should show help when --help flag is used', async () => {
    const cliPath = path.join(process.cwd(), 'dist', 'cli.js')
    
    const result = await new Promise((resolve, reject) => {
      const child = spawn('node', [cliPath, '--help'], {
        stdio: ['pipe', 'pipe', 'pipe']
      })
      
      let stdout = ''
      let stderr = ''
      
      child.stdout.on('data', (data) => {
        stdout += data.toString()
      })
      
      child.stderr.on('data', (data) => {
        stderr += data.toString()
      })
      
      child.on('close', (code) => {
        resolve({ code, stdout, stderr })
      })
      
      child.on('error', reject)
    })

    assert.strictEqual(result.code, 0)
    assert(result.stdout.includes('Usage: dependency-review'))
    assert(result.stdout.includes('Review dependency changes and vulnerabilities'))
    assert(result.stdout.includes('Arguments:'))
    assert(result.stdout.includes('owner'))
    assert(result.stdout.includes('repo'))
    assert(result.stdout.includes('base-ref'))
    assert(result.stdout.includes('head-ref'))
  })

  it('should show version when --version flag is used', async () => {
    const cliPath = path.join(process.cwd(), 'dist', 'cli.js')
    
    const result = await new Promise((resolve, reject) => {
      const child = spawn('node', [cliPath, '--version'], {
        stdio: ['pipe', 'pipe', 'pipe']
      })
      
      let stdout = ''
      let stderr = ''
      
      child.stdout.on('data', (data) => {
        stdout += data.toString()
      })
      
      child.stderr.on('data', (data) => {
        stderr += data.toString()
      })
      
      child.on('close', (code) => {
        resolve({ code, stdout, stderr })
      })
      
      child.on('error', reject)
    })

    assert.strictEqual(result.code, 0)
    assert(result.stdout.includes('1.0.0'))
  })

  it('should fail without GitHub token', async () => {
    const cliPath = path.join(process.cwd(), 'dist', 'cli.js')
    const env = { ...process.env }
    delete env.GITHUB_TOKEN
    
    const result = await new Promise((resolve) => {
      const child = spawn('node', [cliPath, 'owner', 'repo', 'main', 'HEAD'], {
        stdio: ['pipe', 'pipe', 'pipe'],
        env,
        timeout: 5000
      })
      
      let stdout = ''
      let stderr = ''
      
      child.stdout.on('data', (data) => {
        stdout += data.toString()
      })
      
      child.stderr.on('data', (data) => {
        stderr += data.toString()
      })
      
      child.on('close', (code) => {
        resolve({ code, stdout, stderr })
      })
      
      child.on('error', (error) => {
        resolve({ code: 1, stdout, stderr: error.message })
      })
      
      setTimeout(() => {
        child.kill()
        resolve({ code: 1, stdout, stderr: 'Timeout' })
      }, 4000)
    })

    assert.notStrictEqual(result.code, 0)
  })

  it('should handle invalid command line arguments', async () => {
    const cliPath = path.join(process.cwd(), 'dist', 'cli.js')
    
    const result = await new Promise((resolve, reject) => {
      const child = spawn('node', [cliPath, 'not-enough-args'], {
        stdio: ['pipe', 'pipe', 'pipe']
      })
      
      let stdout = ''
      let stderr = ''
      
      child.stdout.on('data', (data) => {
        stdout += data.toString()
      })
      
      child.stderr.on('data', (data) => {
        stderr += data.toString()
      })
      
      child.on('close', (code) => {
        resolve({ code, stdout, stderr })
      })
      
      child.on('error', reject)
    })

    assert.notStrictEqual(result.code, 0)
    assert(result.stderr.includes('error:') || result.stdout.includes('error:'))
  })
})
