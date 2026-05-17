import { type NextRequest, NextResponse } from 'next/server'
import { auth, currentUser } from '@clerk/nextjs/server'
import { signToken, COOKIE_NAME, cookieDomain } from '@/lib/jwt'

// Called by Clerk after successful sign-in. Issues the custom SSO JWT cookie
// on the root domain so nginx auth_request can verify it across all subdomains.
export async function GET(req: NextRequest) {
  const { userId } = await auth()

  if (!userId) {
    return NextResponse.redirect(new URL('/sign-in', req.url))
  }

  const user = await currentUser()
  if (!user) {
    return NextResponse.redirect(new URL('/sign-in', req.url))
  }

  const email = user.emailAddresses[0]?.emailAddress ?? ''
  const name = [user.firstName, user.lastName].filter(Boolean).join(' ')

  const token = await signToken({ sub: userId, email, name })

  const rawRedirect = req.nextUrl.searchParams.get('redirect_url')
  const destination =
    rawRedirect && isAllowedRedirect(rawRedirect)
      ? rawRedirect
      : new URL('/', req.url).toString()

  const response = NextResponse.redirect(destination)
  response.cookies.set(COOKIE_NAME, token, {
    httpOnly: true,
    secure: true,
    sameSite: 'lax',
    domain: cookieDomain() || undefined,
    maxAge: 60 * 60 * 24 * 7,
    path: '/',
  })

  return response
}

function isAllowedRedirect(url: string): boolean {
  try {
    const parsed = new URL(url)
    const allowed = process.env.ALLOWED_REDIRECT_HOSTS?.split(',').map((h) => h.trim()) ?? []
    const ssoHost = process.env.SSO_HOST ?? ''
    return [ssoHost, ...allowed].some((host) => parsed.hostname === host || parsed.hostname.endsWith(`.${host}`))
  } catch {
    return false
  }
}
