-- The trusted-device MFA skip (2026-10-12, the SOTA arc): "Remember
-- this browser" — a deliberate, revocable grant that lets the password
-- alone open the session on a device the holder proved a factor on,
-- GATED by the risk assessment (a new-device or country-change
-- sighting puts the factor back in front — Google's adaptive posture).
-- The cookie carries a 256-bit token; the row holds its SHA-256 (the
-- recovery-code posture). Killed by every credential-replacement act
-- (the reset's wholesale revocation, the console password change, the
-- deactivation) and by the holder from the account console.
CREATE TABLE IF NOT EXISTS mfa_trusted_devices (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL REFERENCES users(id),
  token_hash TEXT NOT NULL,
  user_agent TEXT,
  ip TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  last_used_at TEXT,
  expires_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_mfa_trusted_devices_account ON mfa_trusted_devices (account_id);
