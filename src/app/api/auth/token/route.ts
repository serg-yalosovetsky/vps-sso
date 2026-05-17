import { NextResponse } from 'next/server'
import { auth, currentUser } from '@clerk/nextjs/server'
import { signToken } from '@/lib/jwt'

// Returns a long-lived Bearer token for CLI/script use.
// Requires an active Clerk session (browser must be logged in).
export async function GET() {
  const { userId } = await auth()

  if (!userId) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }

  const user = await currentUser()
  if (!user) {
    return NextResponse.json({ error: 'User not found' }, { status: 404 })
  }

  const email = user.emailAddresses[0]?.emailAddress ?? ''
  const name = [user.firstName, user.lastName].filter(Boolean).join(' ')

  const token = await signToken({ sub: userId, email, name }, '30d')

  return NextResponse.json(
    { token, usage: 'Authorization: Bearer <token>' },
    { headers: { 'Content-Type': 'application/json' } },
  )
}
