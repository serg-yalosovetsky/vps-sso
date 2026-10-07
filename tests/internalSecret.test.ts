import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

// internalSecret.ts кэширует карту секретов на уровне модуля, поэтому каждый
// тест задаёт env и импортирует модуль заново.
async function load(env: Record<string, string | undefined>) {
  vi.resetModules()
  for (const [k, v] of Object.entries(env)) vi.stubEnv(k, v as string)
  return import('../src/lib/internalSecret')
}

const A = 'a'.repeat(64)
const B = 'b'.repeat(64)

describe('normalizeHost', () => {
  it('приводит к нижнему регистру, режет порт и пробелы', async () => {
    const { normalizeHost } = await load({})
    expect(normalizeHost('  Tiles.Example.COM:443 ')).toBe('tiles.example.com')
    expect(normalizeHost(null)).toBe('')
    expect(normalizeHost(undefined)).toBe('')
  })
})

describe('checkInternalSecret', () => {
  beforeEach(() => {
    vi.unstubAllEnvs()
  })
  afterEach(() => {
    vi.unstubAllEnvs()
  })

  it('принимает секрет, выданный именно этому хосту', async () => {
    const { checkInternalSecret } = await load({
      SSO_INTERNAL_SECRETS: JSON.stringify({ 'tiles.example.com': A }),
      SSO_INTERNAL_LEGACY: 'off',
    })
    expect(checkInternalSecret('tiles.example.com', A)).toBe('per-service')
    expect(checkInternalSecret('TILES.example.com:8443', A)).toBe('per-service')
  })

  it('отклоняет секрет сервиса A, предъявленный от имени хоста B', async () => {
    const { checkInternalSecret } = await load({
      SSO_INTERNAL_SECRETS: JSON.stringify({ 'a.example.com': A, 'b.example.com': B }),
      SSO_INTERNAL_LEGACY: 'off',
    })
    expect(checkInternalSecret('b.example.com', A)).toBe('reject')
  })

  it('секрет другой длины даёт reject, а не исключение', async () => {
    const { checkInternalSecret } = await load({
      SSO_INTERNAL_SECRETS: JSON.stringify({ 'a.example.com': A }),
      SSO_INTERNAL_LEGACY: 'off',
    })
    expect(checkInternalSecret('a.example.com', 'short')).toBe('reject')
    expect(checkInternalSecret('a.example.com', null)).toBe('reject')
  })

  it('без карты и без legacy-секрета — misconfigured, а не пропуск', async () => {
    const { checkInternalSecret } = await load({
      SSO_INTERNAL_SECRETS: undefined,
      INTERNAL_SECRET: undefined,
    })
    expect(checkInternalSecret('a.example.com', A)).toBe('misconfigured')
  })

  it('битый JSON карты не открывает доступ', async () => {
    const { checkInternalSecret } = await load({
      SSO_INTERNAL_SECRETS: '{not json',
      SSO_INTERNAL_LEGACY: 'off',
    })
    expect(checkInternalSecret('a.example.com', A)).toBe('misconfigured')
  })

  it('legacy-секрет принимается, пока не выключен', async () => {
    const on = await load({ INTERNAL_SECRET: B })
    expect(on.checkInternalSecret('any.example.com', B)).toBe('legacy')

    const off = await load({ INTERNAL_SECRET: B, SSO_INTERNAL_LEGACY: 'off' })
    expect(off.checkInternalSecret('any.example.com', B)).toBe('misconfigured')
  })
})
