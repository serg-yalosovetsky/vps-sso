import crypto from 'node:crypto'
import { Pool } from 'pg'

// ---------------------------------------------------------------------------
// Opaque service-token validation (Plan B). The GENERAL token layer shared by
// every service behind vps-sso — identity lives in PG (vps_sso.service_tokens),
// we only ever store sha256(token). Revocation = flipping `active`.
//
// verifyServiceToken() THROWS on DB failure on purpose: the caller must fail
// CLOSED (503) rather than fall through to another auth path.
// ---------------------------------------------------------------------------

let pool: Pool | null = null

function getPool(): Pool {
  if (!pool) {
    const url = process.env.VPS_SSO_DB_URL
    if (!url) throw new Error('VPS_SSO_DB_URL not set')
    pool = new Pool({
      connectionString: url,
      max: 4,
      connectionTimeoutMillis: 3000,
      idleTimeoutMillis: 30000,
    })
    // Swallow idle-client errors; the next query re-establishes a connection.
    pool.on('error', () => {})
  }
  return pool
}

// Opaque tokens are minted as `svc_<project>_<base64url>`; JWTs never match.
export function isServiceToken(token: string): boolean {
  return token.startsWith('svc_')
}

function sha256hex(s: string): string {
  return crypto.createHash('sha256').update(s).digest('hex')
}

export type ServiceCheck =
  | { ok: true; principal: string; scopes: unknown }
  | { ok: false; status: 401 | 403 }

// Validate an opaque token for `host`.
//   unknown / revoked / expired -> { ok:false, status:401 }
//   valid but not scoped to host -> { ok:false, status:403 }
//   valid + allowed             -> { ok:true, principal, scopes }
// THROWS on DB error so the caller fails closed.
export async function verifyServiceToken(
  token: string,
  host: string,
): Promise<ServiceCheck> {
  const digest = sha256hex(token)
  const p = getPool()
  const { rows } = await p.query(
    `SELECT id, principal, hosts, is_wildcard, scopes, active, expires_at
       FROM vps_sso.service_tokens
      WHERE token_sha256 = $1`,
    [digest],
  )
  // Unknown token: return silently, WITHOUT an audit write — otherwise a flood
  // of garbage tokens would amplify into a flood of audit inserts.
  if (!rows.length) return { ok: false, status: 401 }

  const r = rows[0]
  const hosts: string[] = Array.isArray(r.hosts) ? r.hosts : []

  let deny: string | null = null
  let status: 401 | 403 = 401
  if (!r.active) deny = 'revoked'
  else if (r.expires_at && new Date(r.expires_at).getTime() <= Date.now())
    deny = 'expired'
  else if (!(r.is_wildcard || hosts.includes(host))) {
    deny = 'wrong_host'
    status = 403
  }

  if (deny) {
    // Known token being misused — worth auditing (spots scope-probing / stale
    // tokens). Best-effort, fire-and-forget, never blocks the auth decision.
    p.query(
      `INSERT INTO vps_sso.token_audit(event, principal, host, detail)
       VALUES ('check_deny', $1, $2, $3)`,
      [r.principal, host, { reason: deny }],
    ).catch(() => {})
    return { ok: false, status }
  }

  // Debounced last-used bump (<=1 write/min per token). Fire-and-forget.
  p.query(
    `UPDATE vps_sso.service_tokens SET last_used_at = now()
       WHERE id = $1
         AND (last_used_at IS NULL OR last_used_at < now() - interval '60 seconds')`,
    [r.id],
  ).catch(() => {})

  return { ok: true, principal: r.principal, scopes: r.scopes }
}
