import { type NextRequest, NextResponse } from 'next/server'
import { verifyAssertion } from '@/lib/assertion'

// ---------------------------------------------------------------------------
// POST /api/auth/verify  — active verification of an X-Sso-Assertion, for
// consumers that prefer an online check over holding the per-consumer key and
// verifying offline (the primary path). Body: { "assertion": "<jwt>" } or the
// header `X-Sso-Assertion`. Returns the assertion's claims on success.
//
// A valid assertion can only be produced by SSO, so the endpoint is a bounded
// oracle (it only echoes what SSO already signed), but we still rate-limit per
// client IP and log failures — it must never become a brute-force / log-flood
// surface.
// ---------------------------------------------------------------------------

// Fixed-window in-memory limiter (Next standalone = single process). Best-effort
// abuse guard, not a security boundary — the signature is the real gate.
const WINDOW_MS = 60_000
const MAX_PER_WINDOW = Number(process.env.SSO_VERIFY_RATE ?? '120')
const hits = new Map<string, { at: number; n: number }>()

function rateLimited(ip: string): boolean {
  const now = Date.now()
  const e = hits.get(ip)
  if (!e || now - e.at >= WINDOW_MS) {
    hits.set(ip, { at: now, n: 1 })
    // Opportunistic sweep so the map can't grow unbounded under churn.
    if (hits.size > 4096) {
      for (const [k, v] of hits) if (now - v.at >= WINDOW_MS) hits.delete(k)
    }
    return false
  }
  e.n += 1
  return e.n > MAX_PER_WINDOW
}

function clientIp(req: NextRequest): string {
  // Prefer X-Real-IP: our nginx (sso.ibotz.fun) sets it to $remote_addr, so it
  // can't be spoofed to rotate around the limiter. X-Forwarded-For is
  // client-supplied (leftmost entry is attacker-controlled) — last resort only.
  const real = req.headers.get('x-real-ip')
  if (real) return real.trim()
  const xff = req.headers.get('x-forwarded-for')
  if (xff) return xff.split(',')[0].trim()
  return 'unknown'
}

export async function POST(req: NextRequest) {
  const ip = clientIp(req)
  if (rateLimited(ip)) {
    return NextResponse.json({ ok: false, error: 'rate_limited' }, { status: 429 })
  }

  let assertion = req.headers.get('x-sso-assertion') ?? ''
  if (!assertion) {
    try {
      const body = (await req.json()) as { assertion?: unknown }
      assertion = typeof body.assertion === 'string' ? body.assertion : ''
    } catch {
      // no/invalid body; falls through to the empty-assertion check below
    }
  }
  if (!assertion) {
    return NextResponse.json({ ok: false, error: 'no_assertion' }, { status: 400 })
  }

  try {
    const v = await verifyAssertion(assertion)
    return NextResponse.json({
      ok: true,
      principal: v.principal,
      host: v.host,
      via: v.via,
      ...(v.email ? { email: v.email } : {}),
      iat: v.iat,
      exp: v.exp,
    })
  } catch (e) {
    // Log failures (journald) so abuse / clock-skew / stale keys are visible;
    // successes are NOT logged to avoid write amplification.
    console.warn(`[verify] reject from ${ip}: ${(e as Error).message}`)
    return NextResponse.json({ ok: false, error: 'invalid_assertion' }, { status: 401 })
  }
}
