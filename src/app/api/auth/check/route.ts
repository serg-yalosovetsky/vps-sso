import { type NextRequest, NextResponse } from 'next/server'
import { verifyToken, COOKIE_NAME } from '@/lib/jwt'
import { isServiceToken, verifyServiceToken } from '@/lib/tokens'

// ---------------------------------------------------------------------------
// Per-service access map: { "email": ["host1", "host2"] } or ["*"] for all.
// LIVE source: config-store (defaults/sso_access), fetched on demand with a
// short TTL cache — editing the map takes effect WITHOUT restarting SSO.
// Fallback: env SSO_ACCESS (snapshot injected by run.sh) when config-store is
// unreachable; then the flat ALLOWED_EMAILS allowlist.
// ---------------------------------------------------------------------------

function parseAccess(obj: unknown): Map<string, Set<string>> | null {
  if (!obj || typeof obj !== 'object') return null
  const m = new Map<string, Set<string>>()
  for (const [email, hosts] of Object.entries(obj as Record<string, unknown>)) {
    if (Array.isArray(hosts)) {
      m.set(
        email.trim().toLowerCase(),
        new Set(hosts.map((h) => String(h).trim().toLowerCase())),
      )
    }
  }
  return m
}

// Env snapshot (run.sh injects SSO_ACCESS from config-store at boot). Used only
// as a fallback when the live fetch fails, so a config-store blip never locks
// everyone out — we serve the last known map instead.
function accessMapFromEnv(): Map<string, Set<string>> | null {
  const raw = process.env.SSO_ACCESS
  if (!raw) return null
  try {
    return parseAccess(JSON.parse(raw))
  } catch {
    return null
  }
}

const ACCESS_TTL_MS = Number(process.env.SSO_ACCESS_TTL_MS ?? '15000')
let accessCache: { at: number; map: Map<string, Set<string>> | null } | null = null

// Fetch the access map from config-store (defaults/sso_access). config-store
// GET returns { value: <string|object> }; the value may be a JSON string.
async function fetchAccessMapLive(): Promise<Map<string, Set<string>> | null> {
  const url = process.env.CONFIG_STORE_URL ?? 'http://100.66.108.118:8782'
  const token = process.env.CONFIG_STORE_TOKEN
  const key = process.env.SSO_ACCESS_KEY ?? 'sso_access'
  if (!token) return null
  try {
    const r = await fetch(`${url}/config/defaults/${key}`, {
      headers: { Authorization: `Bearer ${token}` },
      cache: 'no-store',
    })
    if (!r.ok) return null
    const j = (await r.json()) as { value?: unknown }
    const val = j.value
    const obj = typeof val === 'string' ? JSON.parse(val) : val
    return parseAccess(obj)
  } catch {
    return null
  }
}

// Live map with TTL cache. On live-fetch failure, falls back to the env snapshot
// (also cached briefly, so we don't hammer a down config-store every request).
async function accessMap(): Promise<Map<string, Set<string>> | null> {
  const now = Date.now()
  if (accessCache && now - accessCache.at < ACCESS_TTL_MS) return accessCache.map
  const live = await fetchAccessMapLive()
  const map = live ?? accessMapFromEnv()
  accessCache = { at: now, map }
  return map
}

// Flat allowlist (backwards-compatible). Empty/unset ⇒ any authenticated user.
function allowedEmails(): Set<string> {
  return new Set(
    (process.env.ALLOWED_EMAILS ?? '')
      .split(',')
      .map((e) => e.trim().toLowerCase())
      .filter(Boolean),
  )
}

// True if `email` may access the service at `host`.
async function isAllowed(email: string, host: string): Promise<boolean> {
  const map = await accessMap()
  if (map) {
    const hosts = map.get(email)
    if (!hosts) return false
    return hosts.has('*') || hosts.has(host)
  }
  // Fallback: flat allowlist, service-agnostic.
  const allow = allowedEmails()
  return allow.size === 0 || allow.has(email)
}

// Machine token check (LEGACY JWT-svc path, kept for dual-accept during the
// Plan B migration). A machine token is a JWT signed with the same secret but
// carrying a `svc` claim (string or string[]) naming the service host(s) it may
// reach. Machines deliver it as the sso_token cookie (nginx forwards Cookie,
// not Authorization). Returns the matched host set, or null if not a machine token.
function machineServices(payload: Record<string, unknown>): Set<string> | null {
  const svc = payload.svc
  if (svc === undefined || svc === null) return null
  const list = Array.isArray(svc) ? svc : [svc]
  return new Set(list.map((s) => String(s).trim().toLowerCase()).filter(Boolean))
}

// Called by nginx auth_request on every request to protected services.
// Returns 200 + user headers on success, 401 (no/invalid token), 403 (not allowed here).
export async function GET(req: NextRequest) {
  // INTERNAL_SECRET is now MANDATORY: it is the only proof the caller is our
  // nginx (which injects X-Internal-Secret via the shared snippet). Without it
  // we cannot trust X-Forwarded-Host, so we fail CLOSED rather than open.
  const internalSecret = process.env.INTERNAL_SECRET
  if (!internalSecret) {
    return new NextResponse('SSO misconfigured', { status: 500 })
  }
  if (req.headers.get('x-internal-secret') !== internalSecret) {
    return new NextResponse('Forbidden', { status: 403 })
  }

  const cookie = req.cookies.get(COOKIE_NAME)?.value
  const authHeader = req.headers.get('authorization')
  const token =
    cookie ?? (authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : undefined)

  if (!token) {
    return new NextResponse('Unauthorized', { status: 401 })
  }

  // nginx forwards the target service host as X-Forwarded-Host.
  const host = (req.headers.get('x-forwarded-host') ?? '').toLowerCase()

  // ---- Opaque service-token path (Plan B) --------------------------------
  // svc_<project>_<rand>, validated against PG. On DB failure we fail CLOSED
  // (503) — we never silently downgrade to another auth path.
  if (isServiceToken(token)) {
    let res
    try {
      res = await verifyServiceToken(token, host)
    } catch {
      return new NextResponse('Service Unavailable', { status: 503 })
    }
    if (!res.ok) {
      return new NextResponse(res.status === 403 ? 'Forbidden' : 'Unauthorized', {
        status: res.status,
      })
    }
    return new NextResponse('OK', {
      status: 200,
      headers: {
        'X-Auth-User': res.principal,
        'X-Auth-Email': '',
        'X-Auth-Name': res.principal,
        'X-Sso-Project': res.principal,
      },
    })
  }

  // ---- Legacy JWT paths (human cookie + machine svc-claim) ---------------
  try {
    const payload = await verifyToken(token)

    // Machine token path: scoped by the `svc` claim, independent of the email map.
    const services = machineServices(payload as unknown as Record<string, unknown>)
    if (services) {
      if (!services.has(host)) {
        return new NextResponse('Forbidden', { status: 403 })
      }
      return new NextResponse('OK', {
        status: 200,
        headers: {
          'X-Auth-User': String(payload.sub ?? 'machine'),
          'X-Auth-Email': String(payload.email ?? ''),
          'X-Auth-Name': String(payload.name ?? 'machine'),
        },
      })
    }

    // Human token path: email → allowed hosts (live from config-store).
    const email = (payload.email ?? '').toLowerCase()
    if (!(await isAllowed(email, host))) {
      return new NextResponse('Forbidden', { status: 403 })
    }

    return new NextResponse('OK', {
      status: 200,
      headers: {
        'X-Auth-User': payload.sub,
        'X-Auth-Email': payload.email,
        'X-Auth-Name': payload.name,
      },
    })
  } catch {
    return new NextResponse('Unauthorized', { status: 401 })
  }
}
