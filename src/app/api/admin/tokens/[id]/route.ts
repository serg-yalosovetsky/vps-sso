import { type NextRequest, NextResponse } from 'next/server'
import { currentUser } from '@clerk/nextjs/server'
import { readAccess, isAdmin } from '@/lib/adminAccess'
import { revokeToken } from '@/lib/adminTokens'
import { sameOrigin } from '@/lib/csrf'

export const dynamic = 'force-dynamic'

// DELETE /api/admin/tokens/:id — revoke a token (active -> false). Admin-only.
export async function DELETE(
  req: NextRequest,
  ctx: { params: Promise<{ id: string }> },
) {
  if (!sameOrigin(req)) {
    return NextResponse.json({ error: 'cross-site rejected' }, { status: 403 })
  }
  const user = await currentUser()
  const email = (user?.primaryEmailAddress?.emailAddress ?? user?.emailAddresses[0]?.emailAddress ?? '').toLowerCase()
  if (!email) return NextResponse.json({ error: 'unauthorized' }, { status: 401 })
  const access = await readAccess()
  if (!isAdmin(email, access)) {
    return NextResponse.json({ error: 'forbidden' }, { status: 403 })
  }

  const { id } = await ctx.params
  const n = Number(id)
  if (!Number.isInteger(n) || n <= 0) {
    return NextResponse.json({ error: 'bad id' }, { status: 400 })
  }
  try {
    const row = await revokeToken(n, `sso-admin:${email}`)
    if (!row) {
      return NextResponse.json({ error: 'не найден или уже отозван' }, { status: 404 })
    }
    return NextResponse.json({ ok: true, row })
  } catch (e) {
    return NextResponse.json({ error: (e as Error).message }, { status: 502 })
  }
}
