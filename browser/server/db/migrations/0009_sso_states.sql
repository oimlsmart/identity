-- TODO.identity/04 — the relying party's OIDC sign-in state jar (the
-- /signin/oidc → /callback/oidc round trip's one-time state: the nonce +
-- the PKCE verifier). STORE-BACKED so the Worker's isolates share it —
-- the per-process Map intermittently failed the state check across
-- isolates (the GitHub-flow lesson, retired for SSO too).
CREATE TABLE IF NOT EXISTS sso_states (
  state TEXT PRIMARY KEY,
  nonce TEXT NOT NULL,
  verifier TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at TEXT NOT NULL,
  consumed_at TEXT
);
