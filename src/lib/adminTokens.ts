import crypto from 'node:crypto'
import { Pool } from 'pg'

// ---------------------------------------------------------------------------
// Admin CRUD over the opaque service-token registry (vps_sso.service_tokens) —
// the SAME table the auth path validates against (see lib/tokens.ts). Mirrors
// the `sso-token` CLI so the /admin UI and the CLI stay behaviourally identical.
//
// Raw tokens are shown ONCE at mint and never stored (only sha256). This module
// NEVER returns token_sha256 nor a raw token in listings — mint() is the only
// place a raw token leaves, and only in its return value (shown once in the UI).
// ---------------------------------------------------------------------------

let pool: Pool | null = null
function getPool(): Pool {
  if (!pool) {
    const url = process.env.VPS_SSO_DB_URL
    if (!url) throw new Error('VPS_SSO_DB_URL not set')
    pool = new Pool({
      connectionString: url,
      max: 3,
      connectionTimeoutMillis: 3000,
      idleTimeoutMillis: 30000,
    })
    pool.on('error', () => {})
  }
  return pool
}

export type TokenState = 'active' | 'revoked' | 'expired'
export type TokenRow = {
  id: number
  principal: string
  hosts: string[]
  is_wildcard: boolean
  active: boolean
  label: string | null
  created_by: string | null
  created_at: string | null
  expires_at: string | null
  last_used_at: string | null
  state: TokenState
}

function shape(r: Record<string, unknown>): TokenRow {
  const active = !!r.active
  const expires_at = (r.expires_at as string | null) ?? null
  const state: TokenState = !active
    ? 'revoked'
    : expires_at && new Date(expires_at).getTime() <= Date.now()
      ? 'expired'
      : 'active'
  return {
    id: Number(r.id),
    principal: String(r.principal),
    hosts: Array.isArray(r.hosts) ? (r.hosts as string[]) : [],
    is_wildcard: !!r.is_wildcard,
    active,
    label: (r.label as string | null) ?? null,
    created_by: (r.created_by as string | null) ?? null,
    created_at: (r.created_at as string | null) ?? null,
    expires_at,
    last_used_at: (r.last_used_at as string | null) ?? null,
    state,
  }
}

const COLS = `id, principal, hosts, is_wildcard, active, label, created_by,
              created_at, expires_at, last_used_at`

// List every token (metadata only — never the hash). Newest-active first.
export async function listTokens(includeInactive = true): Promise<TokenRow[]> {
  const p = getPool()
  const { rows } = await p.query(
    `SELECT ${COLS}
       FROM vps_sso.service_tokens
      ${includeInactive ? '' : 'WHERE active = true'}
      ORDER BY active DESC, principal, id DESC`,
  )
  return rows.map(shape)
}

const DUR: Record<string, number> = {
  s: 1e3, m: 60e3, h: 3600e3, d: 86400e3, w: 604800e3, y: 31536000e3,
}
function parseExpiry(s: string | undefined): Date | null {
  if (!s || s === 'never') return null
  const m = /^(\d+)([smhdwy])$/.exec(s)
  if (!m) throw new Error(`неверный expires '${s}' (напр. 90d, 12h, 1y, never)`)
  return new Date(Date.now() + Number(m[1]) * DUR[m[2]])
}

export type MintInput = {
  project: string
  hosts?: string[]
  wildcard?: boolean
  expires?: string
  label?: string
  by: string
}

// Mint a new opaque token. Returns the raw token ONCE (never persisted) plus its
// registry row. Validation mirrors the CLI (project slug, host XOR wildcard).
export async function mintToken(
  input: MintInput,
): Promise<{ token: string; row: TokenRow }> {
  const project = (input.project ?? '').trim().toLowerCase()
  if (!/^[a-z0-9][a-z0-9-]{0,38}$/.test(project))
    throw new Error('project: [a-z0-9-], ≤39 символов, начинается с буквы/цифры')
  const wildcard = !!input.wildcard
  const hosts = (input.hosts ?? []).map((h) => h.trim().toLowerCase()).filter(Boolean)
  if (wildcard && hosts.length) throw new Error('wildcard и host взаимоисключающи')
  if (!wildcard && !hosts.length) throw new Error('нужен host (или явный wildcard)')
  const expiresAt = parseExpiry(input.expires === undefined ? '90d' : input.expires)
  const label = input.label?.trim() || null

  // 256-bit CSPRNG secret, principal-tagged for readability; identity is the row.
  const token = `svc_${project}_${crypto.randomBytes(32).toString('base64url')}`
  const digest = crypto.createHash('sha256').update(token).digest('hex')

  const p = getPool()
  const client = await p.connect()
  try {
    await client.query('BEGIN')
    const { rows } = await client.query(
      `INSERT INTO vps_sso.service_tokens
         (token_sha256, principal, hosts, is_wildcard, scopes, label, created_by, expires_at)
       VALUES ($1,$2,$3,$4,'{}'::jsonb,$5,$6,$7)
       RETURNING ${COLS}`,
      [digest, project, hosts, wildcard, label, input.by, expiresAt],
    )
    await client.query(
      `INSERT INTO vps_sso.token_audit(event, principal, host, detail)
       VALUES ('mint', $1, $2, $3)`,
      [project, hosts.join(',') || '*', { wildcard, by: input.by, via: 'admin-ui' }],
    )
    await client.query('COMMIT')
    return { token, row: shape(rows[0]) }
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {})
    throw e
  } finally {
    client.release()
  }
}

// Revoke by id (active -> false). Returns the row, or null if unknown/already
// revoked. Best-effort audit.
export async function revokeToken(id: number, by: string): Promise<TokenRow | null> {
  const p = getPool()
  const { rows } = await p.query(
    `UPDATE vps_sso.service_tokens SET active = false
      WHERE id = $1 AND active
      RETURNING ${COLS}`,
    [id],
  )
  if (!rows.length) return null
  const row = shape(rows[0])
  await p
    .query(
      `INSERT INTO vps_sso.token_audit(event, principal, host, detail)
       VALUES ('revoke', $1, NULL, $2)`,
      [row.principal, { id, by, via: 'admin-ui' }],
    )
    .catch(() => {})
  return row
}
