import { describe, expect, it, vi } from 'vitest'
import type { NextRequest } from 'next/server'
import { sameOrigin } from '../src/lib/csrf'

function req(headers: Record<string, string>): NextRequest {
  return { headers: new Headers(headers) } as unknown as NextRequest
}

describe('sameOrigin', () => {
  it('пропускает same-origin и прямой заход', () => {
    expect(sameOrigin(req({ 'sec-fetch-site': 'same-origin' }))).toBe(true)
    expect(sameOrigin(req({ 'sec-fetch-site': 'none' }))).toBe(true)
  })
  it('отклоняет cross-site', () => {
    expect(sameOrigin(req({ 'sec-fetch-site': 'cross-site' }))).toBe(false)
  })
  it('без Sec-Fetch-Site сверяет Origin с Host', () => {
    expect(sameOrigin(req({ origin: 'https://sso.example.com', host: 'sso.example.com' }))).toBe(true)
    expect(sameOrigin(req({ origin: 'https://evil.example', host: 'sso.example.com' }))).toBe(false)
    expect(sameOrigin(req({ origin: 'not a url', host: 'sso.example.com' }))).toBe(false)
  })
  it('запрос без браузерных заголовков (curl) пропускается', () => {
    expect(sameOrigin(req({}))).toBe(true)
  })
})

describe('jwt', () => {
  it('без JWT_SECRET модуль не загружается', async () => {
    vi.resetModules()
    vi.stubEnv('JWT_SECRET', '')
    vi.stubEnv('COOKIE_DOMAIN', 'example.com')
    await expect(import('../src/lib/jwt')).rejects.toThrow('JWT_SECRET')
  })

  it('подписанный токен проверяется, чужой подписью — нет', async () => {
    vi.resetModules()
    vi.stubEnv('JWT_SECRET', 'test-secret-0123456789abcdef0123456789')
    vi.stubEnv('COOKIE_DOMAIN', 'example.com')
    const { signToken, verifyToken, cookieDomain } = await import('../src/lib/jwt')
    const t = await signToken({ sub: 'u1', email: 'u1@example.com', name: 'U One' })
    await expect(verifyToken(t)).resolves.toMatchObject({ sub: 'u1', email: 'u1@example.com' })
    expect(cookieDomain()).toBe('example.com')

    const [h, p] = t.split('.')
    await expect(verifyToken(`${h}.${p}.AAAA`)).rejects.toThrow()
  })
})
