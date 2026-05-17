import { ClerkProvider } from '@clerk/nextjs'
import type { Metadata } from 'next'

export const metadata: Metadata = {
  title: 'SSO',
  description: 'Single Sign-On gateway',
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <ClerkProvider>
      <html lang="en">
        <body style={{ margin: 0, fontFamily: 'system-ui, sans-serif' }}>{children}</body>
      </html>
    </ClerkProvider>
  )
}
