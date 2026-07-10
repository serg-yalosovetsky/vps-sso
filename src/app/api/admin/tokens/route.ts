import { type NextRequest, NextResponse } from 'next/server'
import { currentUser } from '@clerk/nextjs/server'
import { readAccess, isAdmin } from '@/lib/adminAccess'
import { listTokens, mintToken } from '@/lib/adminTokens'
import { sameOrigin } from '@/lib/csrf'

// Admin token registry API. Same gate as /api/admin/access: a valid Clerk
// session whose email is an SSO admin. Browser calls carry the Clerk cookie.
export const dynamic = 'force-dynamic'

async function requireAdmin(): Promise<{ email: string } | NextResponse> {
  const user = await currentUser()
  const email = (user?.primaryEmailAddress?.emailAddress ?? user?.emailAddresses[0]?.emailAddress ?? '').toLowerCase()
  if (!email) return NextResponse.json({ error: 'unauthorized' }, { status: 401 })
  const access = await readAccess()
  if (!isAdmin(email, access)) {
    return NextResponse.json({ error: 'forbidden' }, { status: 403 })
  }
  return { email }
}

// GET /api/admin/tokens — list all tokens (metadata only, never the hash/raw).
export async function GET() {
  const gate = await requireAdmin()
  if (gate instanceof NextResponse) return gate
  try {
    return NextResponse.json({ tokens: await listTokens(true) })
  } catch (e) {
    return NextResponse.json({ error: (e as Error).message }, { status: 502 })
  }
}

// POST /api/admin/tokens — mint a token. Returns the raw token ONCE.
export async function POST(req: NextRequest) {
  const gate = await requireAdmin()
  if (gate instanceof NextResponse) return gate

  if (!sameOrigin(req)) {
    return NextResponse.json({ error: 'cross-site rejected' }, { status: 403 })
  }

  let body: Record<string, unknown>
  try {
    body = (await req.json()) as Record<string, unknown>
  } catch {
    return NextResponse.json({ error: 'invalid json' }, { status: 400 })
  }

  const project = String(body.project ?? '')
  const wildcard = !!body.wildcard
  const hosts = Array.isArray(body.hosts)
    ? (body.hosts as unknown[]).map(String)
    : typeof body.hosts === 'string'
      ? (body.hosts as string).split(',')
      : []
  const expires = body.expires != null ? String(body.expires) : undefined
  const label = body.label != null ? String(body.label) : undefined

  try {
    const { token, row } = await mintToken({
      project,
      hosts,
      wildcard,
      expires,
      label,
      by: `sso-admin:${gate.email}`,
    })
    return NextResponse.json({ ok: true, token, row })
  } catch (e) {
    // Validation errors are the common case (bad slug / missing host) -> 400.
    return NextResponse.json({ error: (e as Error).message }, { status: 400 })
  }
}
