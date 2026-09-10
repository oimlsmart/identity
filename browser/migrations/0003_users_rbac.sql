-- Migration 0003 — the RBAC user columns (TODO.federation/12).
-- schema.sql (fresh node DBs) carries these columns in the users CREATE;
-- THIS migration upgrades D1 databases created from 0001+0002. The node
-- store's migrateAuthTables and the D1 store's column probe apply the
-- same adds defensively (a dev database migrated before this file
-- landed).
ALTER TABLE users ADD COLUMN roles TEXT;
ALTER TABLE users ADD COLUMN active INTEGER NOT NULL DEFAULT 1;
