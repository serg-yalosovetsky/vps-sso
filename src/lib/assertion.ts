import { SignJWT, jwtVerify } from 'jose'

// ---------------------------------------------------------------------------
// Signed identity assertions (Plan B, phase 3). On every SUCCESSFUL auth for a
// "consumer" host, SSO mints a short-lived (60s) JWT that cryptographically
// proves "SSO validated <principal> for <host> at <time>". The backend verifies
// it OFFLINE with the same per-consumer key — so even if a client reaches the
// backend directly (bypassing nginx) and spoofs X-Sso-Project, the request has
// no valid assertion and is rejected.
//
// Per-consumer keys: each consumer host has its OWN signing key, so a leaked
// key for one backend cannot forge assertions for another. run.sh materializes
// SSO_ASSERT_KEYS = { "<host>": "<key>" } from config-store (host -> secretName)
// crossed with secrets-gateway (the actual key values). A host absent from the
// map simply gets no assertion — services that don't consume assertions are
// entirely unaffected.
// ---------------------------------------------------------------------------

export const ASSERTION_HEADER = 'X-Sso-Assertion'
export const ASSERTION_ISS = 'sso.ibotz.fun'
const TTL_SECONDS = Number(process.env.SSO_ASSERT_TTL_S ?? '60')

// Parsed once per process; run.sh injects the map at boot, rotation = restart.
let keyCache: Map<string, Uint8Array> | null = null

function keys(): Map<string, Uint8Array> {
  if (keyCache) return keyCache
  const m = new Map<string, Uint8Array>()
  const raw = process.env.SSO_ASSERT_KEYS
  if (raw) {
    try {
      const obj = JSON.parse(raw) as Record<string, unknown>
      for (const [host, k] of Object.entries(obj)) {
        if (typeof k === 'string' && k) {
          m.set(host.trim().toLowerCase(), new TextEncoder().encode(k))
        }
      }
    } catch {
      // Malformed map -> no consumers; assertions simply won't be minted. We
      // never let a bad map break the auth decision itself.
    }
  }
  keyCache = m
  return m
}

export function isAssertionConsumer(host: string): boolean {
  return keys().has(host.trim().toLowerCase())
}

export type AssertionVia = 'service' | 'human' | 'machine'

export interface AssertionClaims {
  principal: string
  via: AssertionVia
  email?: string
}

// Mint an assertion for `host` if it is a registered consumer; otherwise null.
// The `aud` claim binds it to exactly this host, so a backend cannot be handed
// an assertion minted for a different service (no cross-service replay).
export async function mintAssertion(
  host: string,
  claims: AssertionClaims,
): Promise<string | null> {
  const h = host.trim().toLowerCase()
  const key = keys().get(h)
  if (!key) return null
  return new SignJWT({
    via: claims.via,
    ...(claims.email ? { email: claims.email } : {}),
  })
    .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
    .setSubject(claims.principal)
    .setIssuer(ASSERTION_ISS)
    .setAudience(h)
    .setIssuedAt()
    .setExpirationTime(`${TTL_SECONDS}s`)
    .sign(key)
}

export interface VerifiedAssertion {
  principal: string
  host: string
  via: string
  email?: string
  iat: number
  exp: number
}

// Verify an assertion against the key for its own `aud` (a registered consumer
// host). Used by POST /api/auth/verify. Throws on any failure (bad signature,
// expired, unknown consumer, iss/aud mismatch) so the caller returns 401.
export async function verifyAssertion(
  assertion: string,
): Promise<VerifiedAssertion> {
  // Read the unverified aud to pick the right per-consumer key, then verify
  // cryptographically (signature + iss + that same aud + exp) with it.
  const parts = assertion.split('.')
  if (parts.length !== 3) throw new Error('malformed assertion')
  let aud = ''
  try {
    const body = JSON.parse(
      Buffer.from(parts[1], 'base64url').toString('utf8'),
    ) as { aud?: unknown }
    aud = String(Array.isArray(body.aud) ? body.aud[0] : (body.aud ?? '')).toLowerCase()
  } catch {
    throw new Error('malformed assertion')
  }
  const key = keys().get(aud)
  if (!key) throw new Error('unknown consumer')

  const { payload } = await jwtVerify(assertion, key, {
    issuer: ASSERTION_ISS,
    audience: aud,
  })
  return {
    principal: String(payload.sub ?? ''),
    host: aud,
    via: String(payload.via ?? ''),
    email: payload.email ? String(payload.email) : undefined,
    iat: Number(payload.iat ?? 0),
    exp: Number(payload.exp ?? 0),
  }
}
