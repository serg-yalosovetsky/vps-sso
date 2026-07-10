'use client'

import { useState } from 'react'

type TokenState = 'active' | 'revoked' | 'expired'
type TokenRow = {
  id: number
  principal: string
  hosts: string[]
  is_wildcard: boolean
  active: boolean
  label: string | null
  created_by: string | null
  created_at: string | null
  expires_at: string | null
  last_used_at: string | null
  state: TokenState
}

const STATE_COLOR: Record<TokenState, string> = {
  active: '#137333',
  revoked: '#b3261e',
  expired: '#8a6d00',
}

const box: React.CSSProperties = {
  border: '1px solid #e2e2e2',
  borderRadius: 8,
  padding: 16,
  marginTop: 12,
}
const btn: React.CSSProperties = {
  fontSize: 13,
  padding: '5px 10px',
  borderRadius: 6,
  border: '1px solid #d0d0d0',
  background: '#fafafa',
  cursor: 'pointer',
}
const inp: React.CSSProperties = {
  fontSize: 13,
  padding: '6px 8px',
  borderRadius: 6,
  border: '1px solid #d0d0d0',
}
const th: React.CSSProperties = {
  textAlign: 'left',
  padding: '6px 10px',
  fontSize: 11,
  color: '#777',
  fontWeight: 600,
  textTransform: 'uppercase',
  letterSpacing: 0.3,
  borderBottom: '1px solid #eee',
  whiteSpace: 'nowrap',
}
const td: React.CSSProperties = {
  padding: '7px 10px',
  fontSize: 13,
  borderBottom: '1px solid #f2f2f2',
  whiteSpace: 'nowrap',
}

function fmt(ts: string | null, len = 16): string {
  if (!ts) return '—'
  return new Date(ts).toISOString().slice(0, len).replace('T', ' ')
}

export default function TokenManager({ initial }: { initial: TokenRow[] }) {
  const [rows, setRows] = useState<TokenRow[]>(initial)
  const [busy, setBusy] = useState(false)
  const [msg, setMsg] = useState('')
  const [minted, setMinted] = useState<{ token: string; row: TokenRow } | null>(null)

  // mint form
  const [project, setProject] = useState('')
  const [hosts, setHosts] = useState('')
  const [wildcard, setWildcard] = useState(false)
  const [expires, setExpires] = useState('90d')
  const [label, setLabel] = useState('')

  async function refresh() {
    setBusy(true)
    try {
      const r = await fetch('/api/admin/tokens', { cache: 'no-store' })
      const j = await r.json()
      if (r.ok) setRows(j.tokens ?? [])
      else setMsg(`обновление: ${j.error ?? r.status}`)
    } catch (e) {
      setMsg(`обновление: ${(e as Error).message}`)
    } finally {
      setBusy(false)
    }
  }

  async function mint(e: React.FormEvent) {
    e.preventDefault()
    setBusy(true)
    setMsg('')
    setMinted(null)
    try {
      const r = await fetch('/api/admin/tokens', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          project,
          hosts: wildcard ? [] : hosts,
          wildcard,
          expires,
          label,
        }),
      })
      const j = await r.json()
      if (r.ok) {
        setMinted({ token: j.token, row: j.row })
        setProject('')
        setHosts('')
        setLabel('')
        setWildcard(false)
        await refresh()
      } else {
        setMsg(`mint: ${j.error ?? r.status}`)
      }
    } catch (err) {
      setMsg(`mint: ${(err as Error).message}`)
    } finally {
      setBusy(false)
    }
  }

  async function revoke(row: TokenRow) {
    if (!confirm(`Отозвать токен #${row.id} (${row.principal})? Это необратимо.`)) return
    setBusy(true)
    setMsg('')
    try {
      const r = await fetch(`/api/admin/tokens/${row.id}`, { method: 'DELETE' })
      const j = await r.json()
      if (r.ok) await refresh()
      else setMsg(`revoke: ${j.error ?? r.status}`)
    } catch (e) {
      setMsg(`revoke: ${(e as Error).message}`)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div>
      {/* one-time reveal of a freshly minted token */}
      {minted && (
        <div
          style={{
            ...box,
            borderColor: '#137333',
            background: '#f2fbf5',
            marginBottom: 16,
          }}
        >
          <strong style={{ fontSize: 13, color: '#137333' }}>
            Токен создан — скопируй сейчас, позже он невосстановим:
          </strong>
          <div style={{ display: 'flex', gap: 8, marginTop: 8 }}>
            <code
              style={{
                flex: 1,
                fontSize: 12,
                background: '#fff',
                border: '1px solid #cbe6d3',
                borderRadius: 6,
                padding: '8px 10px',
                overflowX: 'auto',
                whiteSpace: 'nowrap',
              }}
            >
              {minted.token}
            </code>
            <button
              type="button"
              style={btn}
              onClick={() => {
                navigator.clipboard?.writeText(minted.token)
                setMsg('скопировано в буфер')
              }}
            >
              Копировать
            </button>
            <button type="button" style={btn} onClick={() => setMinted(null)}>
              Скрыть
            </button>
          </div>
          <div style={{ fontSize: 12, color: '#555', marginTop: 8 }}>
            #{minted.row.id} · principal <code>{minted.row.principal}</code> ·{' '}
            {minted.row.is_wildcard ? '* (wildcard)' : minted.row.hosts.join(', ')} · exp{' '}
            {minted.row.expires_at ? fmt(minted.row.expires_at, 10) : 'never'}
            <br />
            Использование: <code>Authorization: Bearer {minted.token.slice(0, 20)}…</code>
          </div>
        </div>
      )}

      {/* mint form */}
      <form onSubmit={mint} style={box}>
        <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 10 }}>
          Выдать токен
        </div>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 10, alignItems: 'center' }}>
          <input
            style={{ ...inp, width: 150 }}
            placeholder="project (obhid)"
            value={project}
            onChange={(e) => setProject(e.target.value)}
            required
          />
          <input
            style={{ ...inp, width: 240 }}
            placeholder="host(ы): inference.ibotz.fun"
            value={hosts}
            onChange={(e) => setHosts(e.target.value)}
            disabled={wildcard}
          />
          <label style={{ fontSize: 13, display: 'flex', gap: 4, alignItems: 'center' }}>
            <input
              type="checkbox"
              checked={wildcard}
              onChange={(e) => setWildcard(e.target.checked)}
            />
            wildcard (*)
          </label>
          <input
            style={{ ...inp, width: 90 }}
            placeholder="90d"
            value={expires}
            onChange={(e) => setExpires(e.target.value)}
            title="90d / 12h / 1y / never"
          />
          <input
            style={{ ...inp, width: 160 }}
            placeholder="label (опц.)"
            value={label}
            onChange={(e) => setLabel(e.target.value)}
          />
          <button type="submit" style={{ ...btn, fontWeight: 600 }} disabled={busy}>
            Выдать
          </button>
        </div>
        <div style={{ fontSize: 12, color: '#888', marginTop: 8 }}>
          Токен хранится в реестре только как sha256. Хосты через запятую. Ротация =
          выдать новый + отозвать старый.
        </div>
      </form>

      {/* toolbar */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 12,
          marginTop: 20,
          marginBottom: 4,
        }}
      >
        <span style={{ fontSize: 13, color: '#555' }}>
          Всего: {rows.length} · активных:{' '}
          {rows.filter((r) => r.state === 'active').length}
        </span>
        <button type="button" style={btn} onClick={refresh} disabled={busy}>
          {busy ? '…' : 'Обновить'}
        </button>
        {msg && <span style={{ fontSize: 12, color: '#b3261e' }}>{msg}</span>}
      </div>

      {/* table */}
      <div style={{ overflowX: 'auto', border: '1px solid #eee', borderRadius: 8 }}>
        <table style={{ borderCollapse: 'collapse', width: '100%', minWidth: 760 }}>
          <thead>
            <tr>
              <th style={th}>#</th>
              <th style={th}>state</th>
              <th style={th}>principal</th>
              <th style={th}>hosts</th>
              <th style={th}>expires</th>
              <th style={th}>last used</th>
              <th style={th}>by</th>
              <th style={th}>label</th>
              <th style={th}></th>
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 && (
              <tr>
                <td style={{ ...td, color: '#999' }} colSpan={9}>
                  токенов нет
                </td>
              </tr>
            )}
            {rows.map((r) => (
              <tr key={r.id} style={{ opacity: r.state === 'active' ? 1 : 0.55 }}>
                <td style={td}>{r.id}</td>
                <td style={{ ...td, color: STATE_COLOR[r.state], fontWeight: 600 }}>
                  {r.state}
                </td>
                <td style={td}>
                  <code>{r.principal}</code>
                </td>
                <td style={td}>{r.is_wildcard ? '*' : r.hosts.join(', ') || '—'}</td>
                <td style={td}>{r.expires_at ? fmt(r.expires_at, 10) : 'never'}</td>
                <td style={td}>{fmt(r.last_used_at)}</td>
                <td style={{ ...td, color: '#888', fontSize: 12 }}>{r.created_by ?? '—'}</td>
                <td style={{ ...td, color: '#888', fontSize: 12 }}>{r.label ?? ''}</td>
                <td style={td}>
                  {r.state === 'active' ? (
                    <button
                      type="button"
                      style={{ ...btn, color: '#b3261e', borderColor: '#f0caca' }}
                      onClick={() => revoke(r)}
                      disabled={busy}
                    >
                      Отозвать
                    </button>
                  ) : null}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
