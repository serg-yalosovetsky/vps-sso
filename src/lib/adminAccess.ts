// ---------------------------------------------------------------------------
// Admin helpers for the sso_access map (Plan B phase 7). Storage stays in
// config-store (defaults/sso_access) — this module only reads/writes it via the
// same CONFIG_STORE_URL/TOKEN the auth path already uses. Never a secret store.
// ---------------------------------------------------------------------------

export type AccessMap = Record<string, string[]>

const cfgUrl = () => process.env.CONFIG_STORE_URL ?? 'http://100.66.108.118:8782'
const cfgToken = () => process.env.CONFIG_STORE_TOKEN
const accessKey = () => process.env.SSO_ACCESS_KEY ?? 'sso_access'

function normalize(obj: unknown): AccessMap {
  const out: AccessMap = {}
  if (obj && typeof obj === 'object') {
    for (const [email, hosts] of Object.entries(obj as Record<string, unknown>)) {
      if (Array.isArray(hosts)) {
        out[email.trim().toLowerCase()] = hosts
          .map((h) => String(h).trim().toLowerCase())
          .filter(Boolean)
      }
    }
  }
  return out
}

// Read the live map. config-store stores the value as a JSON string.
export async function readAccess(): Promise<AccessMap> {
  const token = cfgToken()
  if (!token) throw new Error('CONFIG_STORE_TOKEN not set')
  const r = await fetch(`${cfgUrl()}/config/defaults/${accessKey()}`, {
    headers: { Authorization: `Bearer ${token}` },
    cache: 'no-store',
  })
  if (!r.ok) throw new Error(`config-store read ${r.status}`)
  const j = (await r.json()) as { value?: unknown }
  const val = j.value
  const obj = typeof val === 'string' ? JSON.parse(val) : val
  return normalize(obj)
}

// Write the map back as a JSON string (matching the existing storage format).
export async function writeAccess(map: AccessMap, by: string): Promise<void> {
  const token = cfgToken()
  if (!token) throw new Error('CONFIG_STORE_TOKEN not set')
  const clean = normalize(map)
  const r = await fetch(`${cfgUrl()}/config/defaults/${accessKey()}`, {
    method: 'PUT',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ value: JSON.stringify(clean), scope: 'defaults', by }),
  })
  if (!r.ok) throw new Error(`config-store write ${r.status}`)
}

// Admins: explicit SSO_ADMIN_EMAILS env if set, else the de-facto admins are the
// wildcard ('*') holders (full access ⇒ may manage the map).
export function adminEmails(access: AccessMap): Set<string> {
  const explicit = (process.env.SSO_ADMIN_EMAILS ?? '')
    .split(',')
    .map((e) => e.trim().toLowerCase())
    .filter(Boolean)
  if (explicit.length) return new Set(explicit)
  const s = new Set<string>()
  for (const [email, hosts] of Object.entries(access)) {
    if (hosts.includes('*')) s.add(email)
  }
  return s
}

export function isAdmin(email: string, access: AccessMap): boolean {
  return adminEmails(access).has(email.trim().toLowerCase())
}
