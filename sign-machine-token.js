// Sign a per-service machine token (HS256, same secret as human SSO cookies).
// The `svc` claim scopes the token to one or more service hosts; auth/check
// treats any token carrying `svc` as a machine token (bypasses the email map).
// Env: JWT_SECRET, SUB, NAME, EMAIL (opt), SVC (comma-sep hosts), EXP (opt, e.g. 3650d).
// Run from /root/vps-sso so `jose` resolves. Prints ONLY the token to stdout.
const { SignJWT } = require('jose')

const secretRaw = process.env.JWT_SECRET
if (!secretRaw) {
  console.error('sign: JWT_SECRET missing')
  process.exit(1)
}
const svc = (process.env.SVC || '')
  .split(',')
  .map((s) => s.trim().toLowerCase())
  .filter(Boolean)
if (svc.length === 0) {
  console.error('sign: SVC (service host) missing')
  process.exit(1)
}

const secret = new TextEncoder().encode(secretRaw)
const payload = {
  sub: process.env.SUB || 'machine',
  name: process.env.NAME || process.env.SUB || 'machine',
  email: process.env.EMAIL || '',
  svc: svc.length === 1 ? svc[0] : svc,
}

;(async () => {
  const jwt = await new SignJWT(payload)
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime(process.env.EXP || '3650d')
    .sign(secret)
  process.stdout.write(jwt)
})().catch((e) => {
  console.error('sign:', e && e.message ? e.message : e)
  process.exit(1)
})
