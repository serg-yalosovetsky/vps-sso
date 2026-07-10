import { currentUser } from '@clerk/nextjs/server'
import { redirect } from 'next/navigation'
import { readAccess, isAdmin } from '@/lib/adminAccess'
import AccessEditor from './AccessEditor'

// Always render fresh (reads the live config-store map).
export const dynamic = 'force-dynamic'

const wrap = { maxWidth: 720, margin: '64px auto', padding: '0 24px' } as const

export default async function AdminPage() {
  const user = await currentUser()
  if (!user) redirect('/sign-in')
  const email = (user.emailAddresses[0]?.emailAddress ?? '').toLowerCase()

  let access: Record<string, string[]> = {}
  let err = ''
  try {
    access = await readAccess()
  } catch (e) {
    err = (e as Error).message
  }

  if (!isAdmin(email, access)) {
    return (
      <main style={wrap}>
        <h1 style={{ fontSize: 22 }}>403 — не администратор</h1>
        <p style={{ color: '#555' }}>
          {email || 'аноним'} не входит в администраторов SSO. Управлять доступом
          могут только держатели <code>*</code> (или список <code>SSO_ADMIN_EMAILS</code>).
        </p>
        <a href="/" style={{ color: '#888', fontSize: 14 }}>← Дашборд</a>
      </main>
    )
  }

  return (
    <main style={wrap}>
      <h1 style={{ fontSize: 22, marginBottom: 4 }}>SSO Access — администрирование</h1>
      <p style={{ color: '#555', marginBottom: 24, fontSize: 14 }}>
        {email} · карта <code>email → хосты</code> (<code>*</code> = все сервисы). Хранится
        в config-store <code>defaults/sso_access</code>, применяется без рестарта SSO.
      </p>
      {err && (
        <p style={{ color: 'crimson', fontSize: 14 }}>config-store: {err}</p>
      )}
      <AccessEditor initial={access} me={email} />
      <div style={{ marginTop: 28 }}>
        <a href="/" style={{ color: '#888', fontSize: 14 }}>← Дашборд</a>
      </div>
    </main>
  )
}
