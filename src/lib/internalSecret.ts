import { timingSafeEqual } from 'crypto'

// ---------------------------------------------------------------------------
// Per-service X-Internal-Secret.
//
// X-Internal-Secret is the ONLY proof that the caller is our nginx. Everything
// downstream — most importantly the client-supplied X-Forwarded-Host, which
// decides WHICH service the request is authorized against — is trusted only
// because this header checked out. A single shared secret therefore meant that
// anyone holding it could claim to be any host: the per-service access map was
// bypassable by construction.
//
// Now every protected host has its OWN secret. nginx picks it from a generated
// `map $host -> $vps_sso_internal_secret`, so the secret a site sends is bound
// to that site. Presenting service A's secret while claiming to be host B fails,
// because we compare against the secret registered for B.
//
// Wiring: config-store defaults/sso_internal_secrets = { "<host>": "<secretName>" },
// values in secrets-gateway under those names, run.sh materializes
// SSO_INTERNAL_SECRETS = { "<host>": "<value>" } at boot. Same shape as
// SSO_ASSERT_KEYS (see assertion.ts) — deliberately one pattern, not two.
// Rotation of any single service = new value in the gateway, re-render the
// nginx map, restart SSO. Rotating one service does NOT disturb the others.
// ---------------------------------------------------------------------------

// Parsed once per process; run.sh injects the map at boot, rotation = restart.
let cache: Map<string, string> | null = null

// $host in nginx is already lowercase and port-less, but X-Forwarded-Host is
// attacker-controlled on any path that reaches us without nginx — normalize
// both sides identically so the lookup cannot be dodged by case or a :port.
export function normalizeHost(h: string | null | undefined): string {
  return (h ?? '').trim().toLowerCase().replace(/:\d+$/, '')
}

function secrets(): Map<string, string> {
  if (cache) return cache
  const m = new Map<string, string>()
  const raw = process.env.SSO_INTERNAL_SECRETS
  if (raw) {
    try {
      const obj = JSON.parse(raw) as Record<string, unknown>
      for (const [host, v] of Object.entries(obj)) {
        if (typeof v === 'string' && v) m.set(normalizeHost(host), v)
      }
    } catch {
      // Malformed map -> no per-service secrets. We do NOT fall open: with the
      // legacy secret retired this yields 'misconfigured' (500), never 200.
    }
  }
  cache = m
  return m
}

// timingSafeEqual THROWS on differing lengths, and an exception on the auth
// path is a 500 — i.e. a malformed header would take the site down. Compare
// lengths first (that much is not secret), then compare contents in constant
// time so the value itself cannot be recovered byte-by-byte via timing.
function constantTimeEquals(a: string, b: string): boolean {
  const ba = Buffer.from(a, 'utf8')
  const bb = Buffer.from(b, 'utf8')
  if (ba.length !== bb.length) return false
  return timingSafeEqual(ba, bb)
}

export type InternalVerdict =
  | 'per-service'   // matched the secret registered for this exact host
  | 'legacy'        // matched the old shared secret (transitional only)
  | 'reject'        // no/!wrong secret, or right secret for a DIFFERENT host
  | 'misconfigured' // nothing to check against — fail closed, never open

// Legacy dual-accept exists ONLY to make the migration downtime-free: SSO must
// accept the old shared secret until every vhost has been switched over to its
// own. Set SSO_INTERNAL_LEGACY=off to complete the cutover.
export function legacyAccepted(): boolean {
  return (process.env.SSO_INTERNAL_LEGACY ?? 'on') !== 'off'
    && (process.env.INTERNAL_SECRET ?? '') !== ''
}

export function checkInternalSecret(
  host: string,
  presented: string | null,
): InternalVerdict {
  const map = secrets()
  const legacyOn = legacyAccepted()

  // No per-service map AND no legacy secret => we cannot authenticate our own
  // nginx at all. Fail closed and loudly rather than trusting X-Forwarded-Host.
  if (map.size === 0 && !legacyOn) return 'misconfigured'
  if (!presented) return 'reject'

  // The whole point: look up the secret for the host being CLAIMED. Service A's
  // secret presented as host B finds B's secret and mismatches -> reject.
  const own = map.get(normalizeHost(host))
  if (own && constantTimeEquals(presented, own)) return 'per-service'

  if (legacyOn && constantTimeEquals(presented, process.env.INTERNAL_SECRET ?? '')) {
    return 'legacy'
  }
  return 'reject'
}

// Diagnostics for startup logging — names and counts only, never values.
export function configuredHosts(): string[] {
  return [...secrets().keys()].sort()
}
