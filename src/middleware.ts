import { clerkMiddleware, createRouteMatcher } from '@clerk/nextjs/server'

const isPublicRoute = createRouteMatcher([
  '/sign-in(.*)',
  '/api/auth/check(.*)',
  '/api/auth/verify(.*)',
  '/api/auth/logout(.*)',
])

export default clerkMiddleware(async (auth, req) => {
  if (!isPublicRoute(req)) {
    await auth.protect()
  }
})

export const config = {
  // NOTE: /api/auth/check and /api/auth/verify are deliberately EXCLUDED from
  // the matcher below, so Clerk middleware never runs on them. They are the
  // machine/backend endpoints and do their own auth (check: internal secret +
  // sso_token cookie / opaque service token; verify: HMAC signature of the
  // assertion + rate limit). If Clerk processed them, a JWT-shaped-but-invalid
  // Authorization: Bearer would trigger Clerk's handshake and 500 the check
  // subrequest, and auth.protect() would 404 the (session-less) verify POST
  // instead of letting the route answer for itself.
  matcher: [
    '/((?!_next|api/auth/check|api/auth/verify|[^?]*\\.(?:html?|css|js(?!on)|jpe?g|webp|png|gif|svg|ttf|woff2?|ico|csv|docx?|xlsx?|zip|webmanifest)).*)',
    '/((?!api/auth/(?:check|verify))(?:api|trpc)(?:/.*)?)',
  ],
}
