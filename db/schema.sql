-- vps_sso: opaque per-project service tokens (Plan B).
-- The general token layer for ALL services behind vps-sso (inference, backstage, ...).
-- Raw tokens are NEVER stored — only their sha256. Revocation = flip `active`.

CREATE SCHEMA IF NOT EXISTS vps_sso;

CREATE TABLE IF NOT EXISTS vps_sso.service_tokens (
  id           bigserial   PRIMARY KEY,
  token_sha256 text        NOT NULL UNIQUE,          -- sha256(hex) of the opaque token
  principal    text        NOT NULL,                 -- project identity, e.g. 'obhid'
  hosts        text[]      NOT NULL DEFAULT '{}',     -- allowed service hosts (lowercased)
  is_wildcard  boolean     NOT NULL DEFAULT false,    -- explicit opt-in for all-hosts token
  scopes       jsonb       NOT NULL DEFAULT '{}'::jsonb,
  active       boolean     NOT NULL DEFAULT true,     -- false = instant revoke
  label        text,
  created_at   timestamptz NOT NULL DEFAULT now(),
  created_by   text,
  expires_at   timestamptz,                           -- NULL = no expiry (discouraged)
  last_used_at timestamptz,
  -- a non-wildcard token must scope at least one host; wildcard must not list hosts
  CONSTRAINT service_tokens_hosts_ck
    CHECK ( (is_wildcard AND cardinality(hosts) = 0)
         OR (NOT is_wildcard AND cardinality(hosts) > 0) )
);

CREATE INDEX IF NOT EXISTS service_tokens_principal_idx
  ON vps_sso.service_tokens (principal);

-- Audit trail for mint/revoke/verify decisions. Cheap, and lets us spot
-- /verify scope-probing (many verify_deny for one token across hosts).
CREATE TABLE IF NOT EXISTS vps_sso.token_audit (
  id        bigserial   PRIMARY KEY,
  at        timestamptz NOT NULL DEFAULT now(),
  event     text        NOT NULL,     -- mint | revoke | verify_ok | verify_deny | check_ok | check_deny
  principal text,
  host      text,
  detail    jsonb       NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS token_audit_at_idx ON vps_sso.token_audit (at DESC);
