import { type NextRequest, NextResponse } from 'next/server'
import { currentUser } from '@clerk/nextjs/server'
import {
  readAccess,
  writeAccess,
  isAdmin,
  adminEmails,
  type AccessMap,
} from '@/lib/adminAccess'

// POST /api/admin/access — replace the sso_access map. Admin-only (Clerk session
// + admin check). Refuses to write a map that would strip the caller's own admin
// access (lockout guard).
export async function POST(req: NextRequest) {
  const user = await currentUser()
  const email = (user?.emailAddresses[0]?.emailAddress ?? '').toLowerCase()
  if (!email) return NextResponse.json({ error: 'unauthorized' }, { status: 401 })

  const current = await readAccess()
  if (!isAdmin(email, current)) {
    return NextResponse.json({ error: 'forbidden' }, { status: 403 })
  }

  let body: unknown
  try {
    body = await req.json()
  } catch {
    return NextResponse.json({ error: 'invalid json' }, { status: 400 })
  }
  const raw = (body as { map?: unknown }).map
  if (!raw || typeof raw !== 'object') {
    return NextResponse.json({ error: 'map required' }, { status: 400 })
  }

  const clean: AccessMap = {}
  for (const [k, v] of Object.entries(raw as Record<string, unknown>)) {
    if (!Array.isArray(v)) {
      return NextResponse.json({ error: `hosts for "${k}" must be an array` }, { status: 400 })
    }
    const e = k.trim().toLowerCase()
    if (!e) continue
    clean[e] = v.map((h) => String(h).trim().toLowerCase()).filter(Boolean)
  }

  // Lockout guard: the caller must remain an admin under the new map (only
  // meaningful in the wildcard-fallback mode; with an explicit SSO_ADMIN_EMAILS
  // env the admin set is fixed and this always passes).
  if (!adminEmails(clean).has(email)) {
    return NextResponse.json(
      { error: 'отказ: эта карта снимает твой собственный админ-доступ (*)' },
      { status: 400 },
    )
  }

  try {
    await writeAccess(clean, `sso-admin:${email}`)
  } catch (e) {
    return NextResponse.json({ error: (e as Error).message }, { status: 502 })
  }
  return NextResponse.json({ ok: true, count: Object.keys(clean).length })
}
