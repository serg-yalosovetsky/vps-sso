import { clerkMiddleware, createRouteMatcher } from '@clerk/nextjs/server'

const isPublicRoute = createRouteMatcher([
  '/sign-in(.*)',
  '/api/auth/check(.*)',
  '/api/auth/logout(.*)',
])

export default clerkMiddleware(async (auth, req) => {
  if (!isPublicRoute(req)) {
    await auth.protect()
  }
})

export const config = {
  // NOTE: /api/auth/check is deliberately EXCLUDED from the matcher below, so
  // Clerk middleware never runs on it. It is the machine/backend auth_request
  // endpoint and does its own auth (internal secret + sso_token cookie /
  // opaque service token). If Clerk processed it, a JWT-shaped-but-invalid
  // Authorization: Bearer (our own or a probe) would trigger Clerk's handshake
  // and 500 the subrequest instead of letting the route answer 401/403.
  matcher: [
    '/((?!_next|api/auth/check|[^?]*\\.(?:html?|css|js(?!on)|jpe?g|webp|png|gif|svg|ttf|woff2?|ico|csv|docx?|xlsx?|zip|webmanifest)).*)',
    '/((?!api/auth/check)(?:api|trpc)(?:/.*)?)',
  ],
}
