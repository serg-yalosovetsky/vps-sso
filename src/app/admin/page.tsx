import Link from 'next/link'
import { currentUser } from '@clerk/nextjs/server'
import { redirect } from 'next/navigation'
import { readAccess, isAdmin } from '@/lib/adminAccess'
import { listTokens, type TokenRow } from '@/lib/adminTokens'
import AccessEditor from './AccessEditor'
import TokenManager from './TokenManager'

// Always render fresh (reads the live config-store map + PG token registry).
export const dynamic = 'force-dynamic'

const wrap = { maxWidth: 980, margin: '64px auto', padding: '0 24px' } as const

export default async function AdminPage() {
  const user = await currentUser()
  if (!user) redirect('/sign-in')
  const email = (user.primaryEmailAddress?.emailAddress ?? user.emailAddresses[0]?.emailAddress ?? '').toLowerCase()

  let access: Record<string, string[]> = {}
  let err = ''
  try {
    access = await readAccess()
  } catch (e) {
    err = (e as Error).message
  }

  if (!isAdmin(email, access)) {
    return (
      <main style={{ maxWidth: 720, margin: '64px auto', padding: '0 24px' }}>
        <h1 style={{ fontSize: 22 }}>403 — не администратор</h1>
        <p style={{ color: '#555' }}>
          {email || 'аноним'} не входит в администраторов SSO. Управлять доступом
          могут только держатели <code>*</code> (или список <code>SSO_ADMIN_EMAILS</code>).
        </p>
        <Link href="/" style={{ color: '#888', fontSize: 14 }}>← Дашборд</Link>
      </main>
    )
  }

  // Token registry (PG). Failure here must not break the access editor above.
  let tokens: TokenRow[] = []
  let tokErr = ''
  try {
    tokens = await listTokens(true)
  } catch (e) {
    tokErr = (e as Error).message
  }

  return (
    <main style={wrap}>
      <h1 style={{ fontSize: 22, marginBottom: 4 }}>SSO — администрирование</h1>
      <p style={{ color: '#555', marginBottom: 24, fontSize: 14 }}>
        {email}
      </p>

      <section>
        <h2 style={{ fontSize: 17, marginBottom: 4 }}>Доступ (люди)</h2>
        <p style={{ color: '#555', marginBottom: 12, fontSize: 13 }}>
          Карта <code>email → хосты</code> (<code>*</code> = все сервисы). Хранится в
          config-store <code>defaults/sso_access</code>, применяется без рестарта SSO.
        </p>
        {err && <p style={{ color: 'crimson', fontSize: 14 }}>config-store: {err}</p>}
        <AccessEditor initial={access} me={email} />
      </section>

      <section style={{ marginTop: 44 }}>
        <h2 style={{ fontSize: 17, marginBottom: 4 }}>Service-токены (машины)</h2>
        <p style={{ color: '#555', marginBottom: 12, fontSize: 13 }}>
          Opaque токены сервисов. Реестр <code>vps_sso.service_tokens</code> (mesh-postgres):
          видно кто что получил, когда использовал — можно отозвать. Хранится только
          sha256; сырой токен показывается один раз при выдаче.
        </p>
        {tokErr ? (
          <p style={{ color: 'crimson', fontSize: 14 }}>реестр (PG) недоступен: {tokErr}</p>
        ) : (
          <TokenManager initial={tokens} />
        )}
      </section>

      <div style={{ marginTop: 32 }}>
        <Link href="/" style={{ color: '#888', fontSize: 14 }}>← Дашборд</Link>
      </div>
    </main>
  )
}
