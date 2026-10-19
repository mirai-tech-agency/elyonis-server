// =============================================================
// SQLite handle + schema migration. Imported by every route
// handler; the same file initializes the DB on first import.
// =============================================================

import Database from 'better-sqlite3';
import { mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';

const DB_PATH = resolve(process.env.DB_PATH ?? './data/licenses.db');
mkdirSync(dirname(DB_PATH), { recursive: true });

export const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');    // concurrent readers + a single writer
db.pragma('foreign_keys = ON');
db.pragma('synchronous = NORMAL');  // good balance for license-scale workloads

// ---------------------------------------------------------------
// Schema. We use a "version" pragma in the schema_meta table so a
// future migration can branch on the previous shape. Right now we
// only have v1.
// ---------------------------------------------------------------
db.exec(`
  CREATE TABLE IF NOT EXISTS schema_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS licenses (
    -- The user-facing license key. Formatted XXXXX-XXXXX-XXXXX-XXXXX-XXXXX
    -- (25 chars from a 32-char alphabet, ~125 bits of entropy).
    key            TEXT PRIMARY KEY,

    -- 'pool'      = generated, not yet activated
    -- 'activated' = locked to a machine
    -- 'revoked'   = admin-revoked, never re-usable
    status         TEXT NOT NULL CHECK (status IN ('pool','activated','revoked')),

    -- The Elyonis-computed machine fingerprint. NULL while in 'pool'.
    machine_id     TEXT,

    activated_at   INTEGER,         -- unix seconds, NULL while in 'pool'
    created_at     INTEGER NOT NULL,
    last_verify_at INTEGER,         -- updated on every /verify hit

    -- 'perpetual'    = never expires
    -- 'subscription' = expires_at must be set
    -- 'trial'        = same as subscription, but capped at 30 days
    type           TEXT NOT NULL CHECK (type IN ('perpetual','subscription','trial')),
    expires_at     INTEGER,         -- unix seconds, NULL = perpetual

    -- Commercial pack, orthogonal to type (type = billing duration,
    -- pack = feature set):
    -- 'basic'   = accessibilité malvoyance (tout l'existant hors dictée)
    -- 'premium' = basic + dictée vocale
    -- 'pro'     = réservé, pas encore commercialisé
    -- Default 'premium': rows created before packs existed had every
    -- feature (dictée incluse) -- grandfather them rather than downgrade.
    pack           TEXT NOT NULL DEFAULT 'premium'
                   CHECK (pack IN ('basic','premium','pro')),

    -- Admin-only metadata: customer name, order id, batch label, etc.
    notes          TEXT
  );

  CREATE INDEX IF NOT EXISTS idx_licenses_machine_id ON licenses(machine_id);
  CREATE INDEX IF NOT EXISTS idx_licenses_status     ON licenses(status);

  -- Audit log: every activation / verify / deactivate / revoke writes
  -- a row here so we can trace abuse patterns and replay state.
  CREATE TABLE IF NOT EXISTS license_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    key         TEXT NOT NULL,
    event       TEXT NOT NULL,      -- 'activate'|'verify'|'deactivate'|'revoke'|'reject'
    machine_id  TEXT,
    ip          TEXT,
    detail      TEXT,               -- short reason for rejects, version info, etc.
    created_at  INTEGER NOT NULL,
    FOREIGN KEY (key) REFERENCES licenses(key)
  );

  CREATE INDEX IF NOT EXISTS idx_events_key  ON license_events(key);
  CREATE INDEX IF NOT EXISTS idx_events_time ON license_events(created_at);
`);

// v1 -> v2: the pack column. ALTER on a live DB (CREATE TABLE IF NOT
// EXISTS above only covers fresh files); the DEFAULT backfills every
// pre-pack row as 'premium' (see the schema comment).
const hasPack = db.prepare(
  `SELECT COUNT(*) AS n FROM pragma_table_info('licenses') WHERE name = 'pack'`
).get().n > 0;
if (!hasPack) {
  db.exec(`
    ALTER TABLE licenses ADD COLUMN pack TEXT NOT NULL DEFAULT 'premium'
      CHECK (pack IN ('basic','premium','pro'))
  `);
}

// Bump schema_meta.version on every breaking migration so we can fail
// fast if an old binary is pointed at a newer DB.
const setVersion = db.prepare(`
  INSERT INTO schema_meta(key,value) VALUES ('version', ?)
  ON CONFLICT(key) DO UPDATE SET value = excluded.value
`);
setVersion.run('2');

// ---------------------------------------------------------------
// Prepared statements -- hot path.
// ---------------------------------------------------------------
export const stmts = {
  findKey: db.prepare('SELECT * FROM licenses WHERE key = ?'),

  // Activation flips pool -> activated and locks the machine_id.
  activate: db.prepare(`
    UPDATE licenses
    SET status = 'activated',
        machine_id = ?,
        activated_at = ?,
        last_verify_at = ?
    WHERE key = ? AND status = 'pool'
  `),

  // Heartbeat: bump last_verify_at on an already-activated key for
  // this machine. Returns rowsChanged so we can tell apart "match" vs
  // "mismatch / revoked".
  touchVerify: db.prepare(`
    UPDATE licenses
    SET last_verify_at = ?
    WHERE key = ? AND machine_id = ? AND status = 'activated'
  `),

  // Deactivate: clear machine_id, return to pool. Only the licensee
  // (proven by matching machine_id) can release a key.
  deactivate: db.prepare(`
    UPDATE licenses
    SET status = 'pool',
        machine_id = NULL,
        activated_at = NULL,
        last_verify_at = NULL
    WHERE key = ? AND machine_id = ? AND status = 'activated'
  `),

  // Admin / bookkeeping.
  insertKey:  db.prepare(`
    INSERT INTO licenses(key, status, created_at, type, expires_at, pack, notes)
    VALUES (?, 'pool', ?, ?, ?, ?, ?)
  `),
  revokeKey:   db.prepare(`UPDATE licenses SET status = 'revoked' WHERE key = ?`),
  extendKey:   db.prepare(`
    UPDATE licenses
    SET expires_at = MAX(COALESCE(expires_at, 0), ?)
    WHERE key = ? AND type != 'perpetual' AND status != 'revoked'
  `),

  // Aggregate counters for the admin dashboard. Expiry is derived rather
  // than stored (nothing sweeps expired rows into a status), so every
  // "is it still live" test has to repeat the isExpired() predicate:
  // perpetual keys and NULL expires_at never expire.
  counts: db.prepare(`
    SELECT
      COUNT(*)                                             AS total,
      SUM(status = 'pool')                                 AS pool,
      SUM(status = 'activated')                            AS activated,
      SUM(status = 'revoked')                              AS revoked,
      SUM(type = 'perpetual')                              AS perpetual,
      SUM(type = 'subscription')                           AS subscription,
      SUM(type = 'trial')                                  AS trial,
      SUM(pack = 'basic')                                  AS pack_basic,
      SUM(pack = 'premium')                                AS pack_premium,
      SUM(pack = 'pro')                                    AS pack_pro,
      SUM(type != 'perpetual' AND expires_at IS NOT NULL
          AND expires_at <= @now)                          AS expired,
      SUM(status = 'activated' AND (type = 'perpetual'
          OR expires_at IS NULL OR expires_at > @now))     AS live_accounts,
      SUM(created_at >= @since24h)                         AS created_24h,
      SUM(created_at >= @since7d)                          AS created_7d,
      SUM(created_at >= @since30d)                         AS created_30d,
      SUM(activated_at IS NOT NULL
          AND activated_at >= @since7d)                    AS activated_7d,
      SUM(activated_at IS NOT NULL
          AND activated_at >= @since30d)                   AS activated_30d
    FROM licenses
  `),

  // Daily buckets for the dashboard sparkline. Two passes (created /
  // activated) rather than one, because a key created on day A and
  // activated on day B belongs to a different bucket in each series.
  createdSeries: db.prepare(`
    SELECT date(created_at, 'unixepoch') AS day, COUNT(*) AS n
    FROM licenses WHERE created_at >= ?
    GROUP BY day ORDER BY day
  `),
  activatedSeries: db.prepare(`
    SELECT date(activated_at, 'unixepoch') AS day, COUNT(*) AS n
    FROM licenses WHERE activated_at IS NOT NULL AND activated_at >= ?
    GROUP BY day ORDER BY day
  `),

  recentEvents: db.prepare(`
    SELECT id, key, event, machine_id, detail, created_at
    FROM license_events ORDER BY created_at DESC, id DESC LIMIT ?
  `),

  logEvent: db.prepare(`
    INSERT INTO license_events(key, event, machine_id, ip, detail, created_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `),
};

export function nowSec() { return Math.floor(Date.now() / 1000); }
