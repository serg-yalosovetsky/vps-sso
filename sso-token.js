#!/usr/bin/env node
// vps_sso token registry CLI: mint / list / revoke / show opaque service tokens.
// Raw tokens are shown ONCE at mint and never stored (only their sha256).
//
// Env (injected by the `sso-token` wrapper):
//   VPS_SSO_DB_URL   postgres connection string (required)
//   MESH_TOKEN       needed only for `mint --store` (PUT into secrets-gateway)
//   SECGW_URL        secrets-gateway base (default http://100.66.108.118:8783)
//   SSO_TOKEN_ACTOR  recorded as created_by (default: unix user)
'use strict'
const crypto = require('crypto')
const { Client } = require('pg')

const SECGW = process.env.SECGW_URL || 'http://100.66.108.118:8783'
const ACTOR = process.env.SSO_TOKEN_ACTOR || `cli:${process.env.USER || 'unknown'}`

// ---- tiny arg parser -------------------------------------------------------
function parseArgs(argv) {
  const out = { _: [] }
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]
    if (a.startsWith('--')) {
      const key = a.slice(2)
      const next = argv[i + 1]
      if (next === undefined || next.startsWith('--')) out[key] = true
      else { out[key] = next; i++ }
    } else out._.push(a)
  }
  return out
}

function sha256(s) { return crypto.createHash('sha256').update(s).digest('hex') }

function parseDuration(s) {
  if (!s || s === 'never') return null
  const m = /^(\d+)([smhdwy])$/.exec(String(s))
  if (!m) throw new Error(`bad --expires '${s}' (use e.g. 90d, 12h, 1y, never)`)
  const n = Number(m[1])
  const unit = { s: 1e3, m: 60e3, h: 3600e3, d: 86400e3, w: 604800e3, y: 31536000e3 }[m[2]]
  return new Date(Date.now() + n * unit)
}

function normHosts(v) {
  if (!v || v === true) return []
  return String(v).split(',').map((h) => h.trim().toLowerCase()).filter(Boolean)
}

async function withDb(fn) {
  const url = process.env.VPS_SSO_DB_URL
  if (!url) { console.error('sso-token: VPS_SSO_DB_URL not set'); process.exit(2) }
  const c = new Client({ connectionString: url })
  await c.connect()
  try { return await fn(c) } finally { await c.end() }
}

async function audit(c, event, principal, host, detail) {
  await c.query(
    'INSERT INTO vps_sso.token_audit(event, principal, host, detail) VALUES ($1,$2,$3,$4)',
    [event, principal || null, host || null, detail || {}],
  )
}

// ---- commands --------------------------------------------------------------
async function cmdMint(args) {
  const project = String(args.project || '').trim().toLowerCase()
  if (!/^[a-z0-9][a-z0-9-]{0,38}$/.test(project))
    throw new Error('--project required, [a-z0-9-], <=39 chars')

  const wildcard = !!args.wildcard
  const hosts = normHosts(args.host)
  if (wildcard && hosts.length) throw new Error('--wildcard and --host are mutually exclusive')
  if (!wildcard && !hosts.length) throw new Error('--host required (or pass --wildcard, deliberately)')

  let scopes = {}
  if (args.scopes && args.scopes !== true) {
    try { scopes = JSON.parse(args.scopes) } catch { throw new Error('--scopes must be JSON') }
  }
  const expiresAt = parseDuration(args.expires === undefined ? '90d' : args.expires)
  const label = args.label && args.label !== true ? String(args.label) : null

  // 256-bit CSPRNG secret; principal-tagged for readability, identity is the row.
  const token = `svc_${project}_${crypto.randomBytes(32).toString('base64url')}`
  const digest = sha256(token)

  await withDb(async (c) => {
    await c.query(
      `INSERT INTO vps_sso.service_tokens
         (token_sha256, principal, hosts, is_wildcard, scopes, label, created_by, expires_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
      [digest, project, hosts, wildcard, scopes, label, ACTOR, expiresAt],
    )
    await audit(c, 'mint', project, hosts.join(',') || '*',
      { wildcard, expires_at: expiresAt, by: ACTOR })
  })

  console.log('# mint OK — copy the token now, it is not recoverable later:\n')
  console.log(token)
  console.log('')
  console.log(`  principal : ${project}`)
  console.log(`  hosts     : ${wildcard ? '* (wildcard)' : hosts.join(', ')}`)
  console.log(`  scopes    : ${JSON.stringify(scopes)}`)
  console.log(`  expires   : ${expiresAt ? expiresAt.toISOString() : 'never'}`)
  console.log(`  usage     : Authorization: Bearer ${token.slice(0, 16)}…`)

  if (args.store) {
    const MT = process.env.MESH_TOKEN
    if (!MT) throw new Error('--store needs MESH_TOKEN in env')
    const slug = (wildcard ? 'WILDCARD' : hosts[0]).replace(/[.-]/g, '_').toUpperCase()
    const key = `SSO_SERVICE_TOKEN_${project.replace(/[.-]/g, '_').toUpperCase()}_${slug}`
    const r = await fetch(`${SECGW}/secrets/${key}`, {
      method: 'PUT',
      headers: { Authorization: `Bearer ${MT}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ value: token, note: `vps_sso service token principal=${project} host=${wildcard ? '*' : hosts.join(',')}` }),
    })
    console.log(`  stored    : ${key} -> HTTP ${r.status}`)
  }
}

async function cmdList(args) {
  await withDb(async (c) => {
    const where = []
    const params = []
    if (args.project && args.project !== true) { params.push(String(args.project).toLowerCase()); where.push(`principal = $${params.length}`) }
    if (!args.all) where.push('active = true AND (expires_at IS NULL OR expires_at > now())')
    const sql = `SELECT id, principal, hosts, is_wildcard, active, expires_at, last_used_at, label
                 FROM vps_sso.service_tokens
                 ${where.length ? 'WHERE ' + where.join(' AND ') : ''}
                 ORDER BY principal, id`
    const { rows } = await c.query(sql, params)
    if (!rows.length) { console.log('(no tokens)'); return }
    for (const r of rows) {
      const hosts = r.is_wildcard ? '*' : (r.hosts || []).join(',')
      const state = !r.active ? 'REVOKED'
        : (r.expires_at && new Date(r.expires_at) < new Date()) ? 'EXPIRED' : 'active'
      const exp = r.expires_at ? new Date(r.expires_at).toISOString().slice(0, 10) : 'never'
      const used = r.last_used_at ? new Date(r.last_used_at).toISOString().slice(0, 16).replace('T', ' ') : '—'
      console.log(`#${String(r.id).padEnd(4)} ${state.padEnd(8)} ${r.principal.padEnd(16)} ${hosts.padEnd(26)} exp:${exp} used:${used}${r.label ? '  ' + r.label : ''}`)
    }
  })
}

async function cmdRevoke(args) {
  await withDb(async (c) => {
    let sql, params
    if (args.id && args.id !== true) { sql = 'UPDATE vps_sso.service_tokens SET active=false WHERE id=$1 AND active RETURNING id, principal'; params = [Number(args.id)] }
    else if (args.sha && args.sha !== true) { sql = 'UPDATE vps_sso.service_tokens SET active=false WHERE token_sha256=$1 AND active RETURNING id, principal'; params = [String(args.sha)] }
    else if (args.project && args.project !== true) { sql = 'UPDATE vps_sso.service_tokens SET active=false WHERE principal=$1 AND active RETURNING id, principal'; params = [String(args.project).toLowerCase()] }
    else throw new Error('revoke needs --id | --sha | --project')
    const { rows } = await c.query(sql, params)
    if (!rows.length) { console.log('(nothing revoked — already inactive or not found)'); return }
    for (const r of rows) { await audit(c, 'revoke', r.principal, null, { id: r.id, by: ACTOR }); console.log(`revoked #${r.id} (${r.principal})`) }
  })
}

const USAGE = `sso-token — vps_sso opaque service tokens
  mint   --project <p> (--host <h[,h2]> | --wildcard) [--scopes '<json>'] [--expires 90d|never] [--label <s>] [--store]
  list   [--project <p>] [--all]
  revoke (--id <n> | --sha <hex> | --project <p>)
  show   --id <n>`

async function cmdShow(args) {
  await withDb(async (c) => {
    const { rows } = await c.query('SELECT * FROM vps_sso.service_tokens WHERE id=$1', [Number(args.id)])
    if (!rows.length) { console.log('(not found)'); return }
    const r = rows[0]; delete r.token_sha256 // never echo even the hash by default? keep it out of casual view
    console.log(JSON.stringify(r, null, 2))
  })
}

async function main() {
  const [cmd, ...rest] = process.argv.slice(2)
  const args = parseArgs(rest)
  try {
    if (cmd === 'mint') await cmdMint(args)
    else if (cmd === 'list') await cmdList(args)
    else if (cmd === 'revoke') await cmdRevoke(args)
    else if (cmd === 'show') await cmdShow(args)
    else { console.log(USAGE); process.exit(cmd ? 1 : 0) }
  } catch (e) {
    console.error(`sso-token: ${e.message}`)
    process.exit(1)
  }
}
main()
