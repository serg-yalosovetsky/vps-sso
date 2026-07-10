import type { NextRequest } from 'next/server'

// Defense-in-depth CSRF guard for state-changing admin endpoints. The Clerk
// session cookie is SameSite=Lax (already not sent on a cross-site POST/DELETE),
// so this is a second layer: browsers always send Sec-Fetch-Site, and a
// cross-site attacker's request carries `cross-site` there. Non-browser callers
// (curl) send neither header and are allowed — the Clerk admin gate still
// applies and an attacker cannot forge that session cookie.
export function sameOrigin(req: NextRequest): boolean {
  const site = req.headers.get('sec-fetch-site')
  if (site) return site === 'same-origin' || site === 'none'
  const origin = req.headers.get('origin')
  if (!origin) return true
  try {
    return new URL(origin).host === req.headers.get('host')
  } catch {
    return false
  }
}
