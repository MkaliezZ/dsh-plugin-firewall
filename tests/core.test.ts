import test from 'node:test'
import assert from 'node:assert/strict'
import { inspectText } from '../src/index.js'

test('flags install scripts and subprocess access as high risk', () => {
  const receipt = inspectText('demo', {
    'package.json': '{"scripts":{"postinstall":"node install.js"}}',
    'index.ts': "import { exec } from 'node:child_process'",
  })
  assert.equal(receipt.risk, 'HIGH')
  assert.ok(receipt.findings.some(f => f.code === 'INSTALL_SCRIPT'))
  assert.ok(receipt.findings.some(f => f.code === 'CHILD_PROCESS'))
})

test('flags network and tool registration as medium risk', () => {
  const receipt = inspectText('demo', { 'index.ts': 'ctx.tools.register({}); fetch("https://example.com")' })
  assert.equal(receipt.risk, 'MEDIUM')
})

test('clean metadata stays low risk', () => {
  const receipt = inspectText('demo', { 'package.json': '{"name":"demo"}' })
  assert.equal(receipt.risk, 'LOW')
})

test('digest is deterministic regardless of input object insertion order', () => {
  const a = inspectText('demo', { 'b.ts': 'process.env.X', 'a.ts': 'fetch("x")' })
  const b = inspectText('demo', { 'a.ts': 'fetch("x")', 'b.ts': 'process.env.X' })
  assert.equal(a.digest, b.digest)
})

test('plugin-firewall command inspects the supplied path', async () => {
  const commands: Record<string, (invocation: { rawInput?: string }) => Promise<{ kind: string; text: string }>> = {}
  const { apply } = await import('../src/index.js')
  apply({ commands: { register: (d: { name: string; handler: unknown }) => { commands[d.name] = d.handler as never } } })
  const result = await commands['plugin-firewall']!({ rawInput: process.cwd() })
  assert.equal(result.kind, 'success')
  const receipt = JSON.parse(result.text)
  assert.equal(typeof receipt.digest, 'string')
  assert.equal(receipt.packageName, '@mkaliezz/dsh-plugin-firewall')
})