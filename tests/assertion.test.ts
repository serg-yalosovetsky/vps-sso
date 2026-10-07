import { describe, expect, it, vi } from 'vitest'
import { SignJWT } from 'jose'

async function load() {
  vi.resetModules()
  vi.stubEnv(
    'SSO_ASSERT_KEYS',
    JSON.stringify({ 'a.example.com': 'key-a-0123456789abcdef', 'b.example.com': 'key-b-0123456789abcdef' }),
  )
  return import('../src/lib/assertion')
}

describe('assertion', () => {
  it('выпускает и проверяет утверждение для зарегистрированного хоста', async () => {
    const { mintAssertion, verifyAssertion } = await load()
    const token = await mintAssertion('A.example.com', { principal: 'u1', via: 'human', email: 'u1@example.com' })
    expect(token).toBeTruthy()
    const v = await verifyAssertion(token as string)
    expect(v).toMatchObject({ principal: 'u1', host: 'a.example.com', via: 'human', email: 'u1@example.com' })
  })

  it('для незарегистрированного хоста ничего не выпускает', async () => {
    const { mintAssertion, isAssertionConsumer } = await load()
    expect(isAssertionConsumer('c.example.com')).toBe(false)
    expect(await mintAssertion('c.example.com', { principal: 'u1', via: 'human' })).toBeNull()
  })

  it('утверждение, подписанное ключом A, но с aud=B, отклоняется', async () => {
    const { verifyAssertion, ASSERTION_ISS } = await load()
    const forged = await new SignJWT({ via: 'human' })
      .setProtectedHeader({ alg: 'HS256' })
      .setSubject('u1')
      .setIssuer(ASSERTION_ISS)
      .setAudience('b.example.com')
      .setIssuedAt()
      .setExpirationTime('60s')
      .sign(new TextEncoder().encode('key-a-0123456789abcdef'))
    await expect(verifyAssertion(forged)).rejects.toThrow()
  })

  it('мусор вместо токена отклоняется', async () => {
    const { verifyAssertion } = await load()
    await expect(verifyAssertion('not-a-jwt')).rejects.toThrow('malformed assertion')
  })
})
