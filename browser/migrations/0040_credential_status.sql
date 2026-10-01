-- TODO.sota/08 slice 2 — the credential status list (RFC 9157): one
-- row per issued credential, its index the bit's position in the
-- compressed list; the revocation act stamps revoked_at (the bit
-- flips). The allocator is the table's own rowid — unique by
-- construction, no read-modify-write races. Expand-only per the
-- migration contract; schema.sql's mirror lands in the same commit.
CREATE TABLE IF NOT EXISTS credential_status (
  idx INTEGER PRIMARY KEY AUTOINCREMENT,
  revoked_at TEXT
);
