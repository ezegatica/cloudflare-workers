-- Migration number: 0001 	 2025-04-22T00:14:37.208Z

-- migrations/0001_initial.sql
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  password TEXT,
  google_id TEXT UNIQUE,
  role TEXT NOT NULL CHECK (role IN ('admin','user')),
  created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);

CREATE TABLE IF NOT EXISTS tokens (
  jti TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  expires_at INTEGER NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0
);

-- Index on tokens user_id for lookups
CREATE INDEX IF NOT EXISTS idx_tokens_user ON tokens(user_id);
