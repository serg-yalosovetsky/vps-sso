import { currentUser } from '@clerk/nextjs/server'
import { redirect } from 'next/navigation'

export default async function Home() {
  const user = await currentUser()

  if (!user) {
    redirect('/sign-in')
  }

  const email = user.emailAddresses[0]?.emailAddress ?? ''
  const name = [user.firstName, user.lastName].filter(Boolean).join(' ')

  return (
    <main style={{ maxWidth: 600, margin: '80px auto', padding: '0 24px' }}>
      <h1 style={{ fontSize: 24, marginBottom: 8 }}>SSO Dashboard</h1>
      <p style={{ color: '#555', marginBottom: 32 }}>
        {name ? `${name} (${email})` : email}
      </p>

      <section style={{ background: '#f5f5f5', borderRadius: 8, padding: 24, marginBottom: 24 }}>
        <h2 style={{ fontSize: 16, marginTop: 0 }}>CLI / API token</h2>
        <p style={{ fontSize: 14, color: '#666', marginBottom: 12 }}>
          Используйте этот токен для доступа из скриптов и CLI через заголовок{' '}
          <code>Authorization: Bearer &lt;token&gt;</code>.
        </p>
        <a
          href="/api/auth/token"
          style={{
            display: 'inline-block',
            padding: '8px 16px',
            background: '#000',
            color: '#fff',
            borderRadius: 6,
            textDecoration: 'none',
            fontSize: 14,
          }}
        >
          Получить токен (30 дней)
        </a>
      </section>

      <a
        href="/api/auth/logout"
        style={{ color: '#888', fontSize: 14, textDecoration: 'none' }}
      >
        Выйти
      </a>
    </main>
  )
}
