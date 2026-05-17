import { SignJWT, jwtVerify, type JWTPayload } from 'jose'

export const COOKIE_NAME = 'sso_token'

if (!process.env.JWT_SECRET) {
  throw new Error('JWT_SECRET env var is required')
}
if (!process.env.COOKIE_DOMAIN) {
  throw new Error('COOKIE_DOMAIN env var is required (e.g. example.com)')
}

const secret = new TextEncoder().encode(process.env.JWT_SECRET)

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
    .sign(secret)
}

export async function verifyToken(token: string): Promise<SSOPayload> {
  const { payload } = await jwtVerify(token, secret)
  return payload as SSOPayload
}

export function cookieDomain(): string {
  return process.env.COOKIE_DOMAIN ?? ''
}
