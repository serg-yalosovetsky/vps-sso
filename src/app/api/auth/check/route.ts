import { type NextRequest, NextResponse } from 'next/server'
import { verifyToken, COOKIE_NAME } from '@/lib/jwt'

// Per-service access map: { "email": ["host1", "host2"] } or ["*"] for all services.
// Source: config-store (defaults/sso_access), injected into env SSO_ACCESS by run.sh.
// Falls back to the flat ALLOWED_EMAILS allowlist when SSO_ACCESS is unset/invalid.
function accessMap(): Map<string, Set<string>> | null {
  const raw = process.env.SSO_ACCESS
  if (!raw) return null
  try {
    const obj = JSON.parse(raw) as Record<string, string[]>
    const m = new Map<string, Set<string>>()
    for (const [email, hosts] of Object.entries(obj)) {
      if (Array.isArray(hosts)) {
        m.set(email.trim().toLowerCase(), new Set(hosts.map((h) => h.trim().toLowerCase())))
      }
    }
    return m
  } catch {
    return null
  }
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
function isAllowed(email: string, host: string): boolean {
  const map = accessMap()
  if (map) {
    const hosts = map.get(email)
    if (!hosts) return false
    return hosts.has('*') || hosts.has(host)
  }
  // Fallback: flat allowlist, service-agnostic.
  const allow = allowedEmails()
  return allow.size === 0 || allow.has(email)
}

// Called by nginx auth_request on every request to protected services.
// Returns 200 + user headers on success, 401 (no/invalid token), 403 (not allowed here).
export async function GET(req: NextRequest) {
  const internalSecret = process.env.INTERNAL_SECRET
  if (internalSecret) {
    const provided = req.headers.get('x-internal-secret')
    if (provided !== internalSecret) {
      return new NextResponse('Forbidden', { status: 403 })
    }
  }

  const cookie = req.cookies.get(COOKIE_NAME)?.value
  const authHeader = req.headers.get('authorization')
  const token =
    cookie ?? (authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : undefined)

  if (!token) {
    return new NextResponse('Unauthorized', { status: 401 })
  }

  try {
    const payload = await verifyToken(token)
    const email = (payload.email ?? '').toLowerCase()
    // nginx forwards the target service host as X-Forwarded-Host.
    const host = (req.headers.get('x-forwarded-host') ?? '').toLowerCase()

    if (!isAllowed(email, host)) {
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
