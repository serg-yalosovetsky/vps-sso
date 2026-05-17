'use client'

import { SignIn } from '@clerk/nextjs'
import { useSearchParams } from 'next/navigation'
import { Suspense } from 'react'

function SignInForm() {
  const searchParams = useSearchParams()
  const redirectUrl = searchParams.get('redirect_url')

  const callbackUrl = redirectUrl
    ? `/api/auth/callback?redirect_url=${encodeURIComponent(redirectUrl)}`
    : '/api/auth/callback'

  return (
    <SignIn
      forceRedirectUrl={callbackUrl}
      appearance={{ elements: { rootBox: { margin: 'auto' } } }}
    />
  )
}

export default function SignInPage() {
  return (
    <div
      style={{
        display: 'flex',
        justifyContent: 'center',
        alignItems: 'center',
        minHeight: '100vh',
        background: '#fafafa',
      }}
    >
      <Suspense>
        <SignInForm />
      </Suspense>
    </div>
  )
}
