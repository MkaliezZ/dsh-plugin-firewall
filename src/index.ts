import { createHash } from 'node:crypto'
import { readFile, readdir } from 'node:fs/promises'
import { join } from 'node:path'

export type Severity = 'LOW' | 'MEDIUM' | 'HIGH'
export interface Finding { code: string; severity: Severity; evidence: string }
export interface Receipt { packageName: string; findings: Finding[]; risk: Severity; digest: string }

const HIGH_PATTERNS: [string, RegExp][] = [
  ['INSTALL_SCRIPT', /"(?:preinstall|install|postinstall)"\s*:/],
  ['NATIVE_ADDON', /\.node\b|node-gyp|prebuild-install/],
  ['CHILD_PROCESS', /node:child_process|child_process|\bspawn\(|\bexec\(/],
]
const MEDIUM_PATTERNS: [string, RegExp][] = [
  ['NETWORK_ACCESS', /node:https?|fetch\(|axios|undici/],
  ['ENV_ACCESS', /process\.env/],
  ['FILESYSTEM_ACCESS', /node:fs|from ['"]fs['"]/],
  ['TOOL_REGISTRATION', /tools\.(?:register|provide)|ctx\.tools/],
  ['PROFILE_PATCH', /cordis\.patch|profile/i],
  ['REMOTE_DEPENDENCY', /(?:git\+https?|https?):\/\//],
]

function riskOf(findings: Finding[]): Severity {
  if (findings.some(f => f.severity === 'HIGH')) return 'HIGH'
  if (findings.some(f => f.severity === 'MEDIUM')) return 'MEDIUM'
  return 'LOW'
}

export function inspectText(packageName: string, files: Record<string, string>): Receipt {
  const findings: Finding[] = []
  for (const [path, text] of Object.entries(files).sort(([a], [b]) => a.localeCompare(b))) {
    for (const [code, re] of HIGH_PATTERNS) if (re.test(text)) findings.push({ code, severity: 'HIGH', evidence: path })
    for (const [code, re] of MEDIUM_PATTERNS) if (re.test(text)) findings.push({ code, severity: 'MEDIUM', evidence: path })
  }
  const canonical = JSON.stringify({ packageName, findings })
  return { packageName, findings, risk: riskOf(findings), digest: createHash('sha256').update(canonical).digest('hex') }
}

export async function inspectDirectory(root: string): Promise<Receipt> {
  const files: Record<string, string> = {}
  const packagePath = join(root, 'package.json')
  const pkgText = await readFile(packagePath, 'utf8')
  files['package.json'] = pkgText
  const pkg = JSON.parse(pkgText) as { name?: string }
  for (const name of await readdir(root)) {
    if (!/\.(?:ts|js|mjs|cjs|json|ya?ml)$/.test(name) || name === 'package.json') continue
    try { files[name] = await readFile(join(root, name), 'utf8') } catch { /* bounded root-only v0.1 */ }
  }
  return inspectText(pkg.name ?? 'unknown', files)
}

export const name = 'plugin-firewall'
export const inject = ['commands']
export function apply(ctx: any): void {
  ctx.commands.register({
    name: 'plugin-firewall',
    description: 'Statically inspect a local DSH plugin package without executing it.',
    recordInput: false,
    async handler(invocation: any) {
      const target = String(invocation.rawInput ?? '').trim() || '.'
      const receipt = await inspectDirectory(target)
      return { kind: 'success', text: JSON.stringify(receipt, null, 2) }
    },
  })
}
