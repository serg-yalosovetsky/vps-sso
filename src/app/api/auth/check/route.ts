import { type NextRequest, NextResponse } from 'next/server'
import { verifyToken, COOKIE_NAME } from '@/lib/jwt'

// Called by nginx auth_request on every request to protected services.
// Returns 200 + user headers on success, 401 on failure.
export async function GET(req: NextRequest) {
  const internalSecret = process.env.INTERNAL_SECRET
  if (internalSecret) {
    const provided = req.headers.get('x-internal-secret')
    if (provided !== internalSecret) {
      return new NextResponse('Forbidden', { status: 403 })
    }
  }

  const cookie = req.cookies.get(COOKIE_NAME)?.value
  const authHeader = req.headers.get('authorization')
  const token =
    cookie ?? (authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : undefined)

  if (!token) {
    return new NextResponse('Unauthorized', { status: 401 })
  }

  try {
    const payload = await verifyToken(token)
    return new NextResponse('OK', {
      status: 200,
      headers: {
        'X-Auth-User': payload.sub,
        'X-Auth-Email': payload.email,
        'X-Auth-Name': payload.name,
      },
    })
  } catch {
    return new NextResponse('Unauthorized', { status: 401 })
  }
}
