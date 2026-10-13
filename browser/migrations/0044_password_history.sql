-- 0044 — the password history (2026-10-13, the GitHub/Google parity):
-- the last FIVE hashes per account are kept, and every landing surface
-- (the self reset, the enroll link, the console change) refuses a
-- password matching any of them — reset-to-the-compromised-password
-- defeats the reset's own sweep, so it is refused like Google and
-- GitHub refuse it. The hashes are the PBKDF2 storage form; the
-- plaintext is never here.
CREATE TABLE IF NOT EXISTS password_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT NOT NULL,
  hash TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_password_history_user ON password_history (user_id, id);
