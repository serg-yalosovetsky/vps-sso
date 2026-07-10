'use client'

import { useState } from 'react'

type Row = { email: string; hosts: string }
type Map = Record<string, string[]>

function toRows(m: Map): Row[] {
  return Object.entries(m).map(([email, hosts]) => ({ email, hosts: hosts.join(', ') }))
}

const cell = { padding: '6px 8px', border: '1px solid #ddd', fontSize: 14 } as const
const input = { width: '100%', border: 'none', outline: 'none', fontSize: 14, fontFamily: 'inherit' } as const
const btn = {
  padding: '8px 16px', borderRadius: 6, border: 'none', fontSize: 14, cursor: 'pointer',
} as const

export default function AccessEditor({ initial, me }: { initial: Map; me: string }) {
  const [rows, setRows] = useState<Row[]>(toRows(initial))
  const [status, setStatus] = useState('')
  const [saving, setSaving] = useState(false)

  const setRow = (i: number, k: keyof Row, v: string) =>
    setRows(rows.map((r, j) => (j === i ? { ...r, [k]: v } : r)))
  const addRow = () => setRows([...rows, { email: '', hosts: '' }])
  const delRow = (i: number) => setRows(rows.filter((_, j) => j !== i))

  const save = async () => {
    setSaving(true)
    setStatus('')
    const map: Map = {}
    for (const r of rows) {
      const e = r.email.trim().toLowerCase()
      if (!e) continue
      map[e] = r.hosts.split(',').map((h) => h.trim().toLowerCase()).filter(Boolean)
    }
    try {
      const res = await fetch('/api/admin/access', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ map }),
      })
      const j = (await res.json()) as { ok?: boolean; error?: string }
      setStatus(res.ok ? '✓ Сохранено' : `Ошибка: ${j.error ?? res.status}`)
    } catch (e) {
      setStatus(`Ошибка: ${(e as Error).message}`)
    }
    setSaving(false)
  }

  return (
    <div>
      <table style={{ width: '100%', borderCollapse: 'collapse', marginBottom: 12 }}>
        <thead>
          <tr>
            <th style={{ ...cell, textAlign: 'left', background: '#f5f5f5', width: '45%' }}>email</th>
            <th style={{ ...cell, textAlign: 'left', background: '#f5f5f5' }}>хосты (через запятую, * = все)</th>
            <th style={{ ...cell, background: '#f5f5f5', width: 40 }} />
          </tr>
        </thead>
        <tbody>
          {rows.map((r, i) => (
            <tr key={i}>
              <td style={cell}>
                <input
                  style={input}
                  value={r.email}
                  placeholder="user@example.com"
                  onChange={(e) => setRow(i, 'email', e.target.value)}
                />
              </td>
              <td style={cell}>
                <input
                  style={input}
                  value={r.hosts}
                  placeholder="chats.ibotz.fun, links.ibotz.fun"
                  onChange={(e) => setRow(i, 'hosts', e.target.value)}
                />
              </td>
              <td style={{ ...cell, textAlign: 'center' }}>
                <button
                  onClick={() => delRow(i)}
                  title="Удалить строку"
                  style={{ ...btn, background: 'transparent', color: '#c00', padding: 2 }}
                >
                  ✕
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
        <button onClick={addRow} style={{ ...btn, background: '#eee', color: '#000' }}>
          + строка
        </button>
        <button
          onClick={save}
          disabled={saving}
          style={{ ...btn, background: '#000', color: '#fff', opacity: saving ? 0.6 : 1 }}
        >
          {saving ? 'Сохранение…' : 'Сохранить'}
        </button>
        <span style={{ fontSize: 14, color: status.startsWith('✓') ? 'green' : 'crimson' }}>
          {status}
        </span>
      </div>
      <p style={{ fontSize: 12, color: '#999', marginTop: 12 }}>
        Ты — <code>{me}</code>. Нельзя снять админ-доступ у самого себя (защита от локаута).
      </p>
    </div>
  )
}
