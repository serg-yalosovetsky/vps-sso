import { SignJWT, jwtVerify, type JWTPayload } from 'jose'

export const COOKIE_NAME = 'sso_token'

// Проверка env — при первом использовании, а не при импорте модуля. `next build`
// импортирует роуты, чтобы собрать page data, и проверка на импорте требовала
// рантайм-секрет на этапе сборки: узел раскатки собирает без него, и сборка
// прода падала (07.10.2026, serg/tasks#1585). Fail-closed сохранён: без
// JWT_SECRET любой вызов бросает, запрос получает 500, а не пропуск.
let secret: Uint8Array | null = null

function getSecret(): Uint8Array {
  if (secret) return secret
  if (!process.env.JWT_SECRET) {
    throw new Error('JWT_SECRET env var is required')
  }
  secret = new TextEncoder().encode(process.env.JWT_SECRET)
  return secret
}

export interface SSOPayload extends JWTPayload {
  sub: string
  email: string
  name: string
}

export async function signToken(
  payload: Pick<SSOPayload, 'sub' | 'email' | 'name'>,
  expiresIn: string = '7d',
): Promise<string> {
  return new SignJWT({ ...payload })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime(expiresIn)
    .sign(getSecret())
}

export async function verifyToken(token: string): Promise<SSOPayload> {
  const { payload } = await jwtVerify(token, getSecret())
  return payload as SSOPayload
}

export function cookieDomain(): string {
  const d = process.env.COOKIE_DOMAIN
  if (!d) {
    throw new Error('COOKIE_DOMAIN env var is required (e.g. example.com)')
  }
  return d
}
