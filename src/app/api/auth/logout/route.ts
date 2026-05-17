import { type NextRequest, NextResponse } from 'next/server'
import { auth, clerkClient } from '@clerk/nextjs/server'
import { COOKIE_NAME, cookieDomain } from '@/lib/jwt'

// Hard logout: revokes the Clerk session server-side, then clears the SSO cookie.
// Listed as a public route in middleware so it works even if Clerk session is already expired.
export async function GET(req: NextRequest) {
  const { sessionId } = await auth()

  if (sessionId) {
    try {
      const client = await clerkClient()
      await client.sessions.revokeSession(sessionId)
    } catch {
      // Session may already be gone — still clear the SSO cookie
    }
  }

  const ssoHost = process.env.SSO_HOST ?? req.nextUrl.host
  const response = NextResponse.redirect(`https://${ssoHost}/sign-in`)
  response.cookies.set(COOKIE_NAME, '', {
    httpOnly: true,
    secure: true,
    sameSite: 'lax',
    domain: cookieDomain(),
    maxAge: 0,
    path: '/',
  })
  return response
}
