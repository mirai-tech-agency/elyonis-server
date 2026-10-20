// =============================================================
// Postgres (Neon) pool + schema migration. Imported by every route
// handler; the same file initializes the schema on first import.
// =============================================================

import pg from 'pg';

const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) {
    console.error('DATABASE_URL env var missing (Neon connection string).');
    process.exit(1);
}

// Every timestamp is unix seconds in a BIGINT and every COUNT() is a
// BIGINT too. pg returns int8 as a string by default (it can exceed
// 2^53); our values never do, so hand them back as plain numbers --
// the JSON shapes stay identical to the SQLite era.
pg.types.setTypeParser(pg.types.builtins.INT8, v => parseInt(v, 10));

export const pool = new pg.Pool({
    connectionString: DATABASE_URL,
    max: 5,                     // license-scale traffic; Neon pools server-side too
    idleTimeoutMillis: 30_000,
});
pool.on('error', e => console.error('pg pool error:', e.message));

// Thin helpers so call sites read like the old better-sqlite3 ones.
export async function all(sql, params = []) { return (await pool.query(sql, params)).rows; }
export async function get(sql, params = []) { return (await pool.query(sql, params)).rows[0]; }
export async function run(sql, params = []) {
    return { changes: (await pool.query(sql, params)).rowCount };
}

// ---------------------------------------------------------------
// Schema. We use a "version" row in the schema_meta table so a
// future migration can branch on the previous shape. v2 = the
// SQLite schema (with pack) carried over to Postgres as-is.
// ---------------------------------------------------------------
await pool.query(`
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

    activated_at   BIGINT,          -- unix seconds, NULL while in 'pool'
    created_at     BIGINT NOT NULL,
    last_verify_at BIGINT,          -- updated on every /verify hit

    -- 'perpetual'    = never expires
    -- 'subscription' = expires_at must be set
    -- 'trial'        = same as subscription, but capped at 30 days
    type           TEXT NOT NULL CHECK (type IN ('perpetual','subscription','trial')),
    expires_at     BIGINT,          -- unix seconds, NULL = perpetual

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
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    key         TEXT NOT NULL REFERENCES licenses(key),
    event       TEXT NOT NULL,      -- 'activate'|'verify'|'deactivate'|'revoke'|'reject'
    machine_id  TEXT,
    ip          TEXT,
    detail      TEXT,               -- short reason for rejects, version info, etc.
    created_at  BIGINT NOT NULL
  );

  CREATE INDEX IF NOT EXISTS idx_events_key  ON license_events(key);
  CREATE INDEX IF NOT EXISTS idx_events_time ON license_events(created_at);

  -- Bump on every breaking migration so we can fail fast if an old
  -- binary is pointed at a newer DB.
  INSERT INTO schema_meta(key,value) VALUES ('version', '2')
  ON CONFLICT(key) DO UPDATE SET value = excluded.value;
`);

// ---------------------------------------------------------------
// Statements -- hot path. Each is async and mirrors the old
// prepared-statement API: get() -> row|undefined, run() -> {changes}.
// ---------------------------------------------------------------
const DAY_SQL = col => `to_char(to_timestamp(${col}) AT TIME ZONE 'UTC', 'YYYY-MM-DD')`;

export const stmts = {
    findKey: key => get('SELECT * FROM licenses WHERE key = $1', [key]),

    // Activation flips pool -> activated and locks the machine_id.
    activate: (machineId, activatedAt, verifyAt, key) => run(`
        UPDATE licenses
        SET status = 'activated',
            machine_id = $1,
            activated_at = $2,
            last_verify_at = $3
        WHERE key = $4 AND status = 'pool'
    `, [machineId, activatedAt, verifyAt, key]),

    // Heartbeat: bump last_verify_at on an already-activated key for
    // this machine. Returns changes so we can tell apart "match" vs
    // "mismatch / revoked".
    touchVerify: (now, key, machineId) => run(`
        UPDATE licenses
        SET last_verify_at = $1
        WHERE key = $2 AND machine_id = $3 AND status = 'activated'
    `, [now, key, machineId]),

    // Deactivate: clear machine_id, return to pool. Only the licensee
    // (proven by matching machine_id) can release a key.
    deactivate: (key, machineId) => run(`
        UPDATE licenses
        SET status = 'pool',
            machine_id = NULL,
            activated_at = NULL,
            last_verify_at = NULL
        WHERE key = $1 AND machine_id = $2 AND status = 'activated'
    `, [key, machineId]),

    // Admin / bookkeeping. `db` lets a caller run it on a transaction client.
    insertKey: (key, now, type, expiresAt, pack, notes, db = pool) => db.query(`
        INSERT INTO licenses(key, status, created_at, type, expires_at, pack, notes)
        VALUES ($1, 'pool', $2, $3, $4, $5, $6)
    `, [key, now, type, expiresAt, pack, notes]),
    revokeKey: key => run(`UPDATE licenses SET status = 'revoked' WHERE key = $1`, [key]),
    extendKey: (expiresAt, key) => run(`
        UPDATE licenses
        SET expires_at = GREATEST(COALESCE(expires_at, 0), $1)
        WHERE key = $2 AND type != 'perpetual' AND status != 'revoked'
    `, [expiresAt, key]),
    resetKey: key => run(`
        UPDATE licenses
        SET status='pool', machine_id=NULL,
            activated_at=NULL, last_verify_at=NULL
        WHERE key = $1 AND status != 'revoked'
    `, [key]),

    // Aggregate counters for the admin dashboard. Expiry is derived rather
    // than stored (nothing sweeps expired rows into a status), so every
    // "is it still live" test has to repeat the isExpired() predicate:
    // perpetual keys and NULL expires_at never expire.
    counts: ({ now, since24h, since7d, since30d }) => get(`
        SELECT
          COUNT(*)                                                  AS total,
          COUNT(*) FILTER (WHERE status = 'pool')                   AS pool,
          COUNT(*) FILTER (WHERE status = 'activated')              AS activated,
          COUNT(*) FILTER (WHERE status = 'revoked')                AS revoked,
          COUNT(*) FILTER (WHERE type = 'perpetual')                AS perpetual,
          COUNT(*) FILTER (WHERE type = 'subscription')             AS subscription,
          COUNT(*) FILTER (WHERE type = 'trial')                    AS trial,
          COUNT(*) FILTER (WHERE pack = 'basic')                    AS pack_basic,
          COUNT(*) FILTER (WHERE pack = 'premium')                  AS pack_premium,
          COUNT(*) FILTER (WHERE pack = 'pro')                      AS pack_pro,
          COUNT(*) FILTER (WHERE type != 'perpetual' AND expires_at IS NOT NULL
                           AND expires_at <= $1)                    AS expired,
          COUNT(*) FILTER (WHERE status = 'activated' AND (type = 'perpetual'
                           OR expires_at IS NULL OR expires_at > $1)) AS live_accounts,
          COUNT(*) FILTER (WHERE created_at >= $2)                  AS created_24h,
          COUNT(*) FILTER (WHERE created_at >= $3)                  AS created_7d,
          COUNT(*) FILTER (WHERE created_at >= $4)                  AS created_30d,
          COUNT(*) FILTER (WHERE activated_at >= $3)                AS activated_7d,
          COUNT(*) FILTER (WHERE activated_at >= $4)                AS activated_30d
        FROM licenses
    `, [now, since24h, since7d, since30d]),

    // Daily buckets for the dashboard sparkline. Two passes (created /
    // activated) rather than one, because a key created on day A and
    // activated on day B belongs to a different bucket in each series.
    createdSeries: since => all(`
        SELECT ${DAY_SQL('created_at')} AS day, COUNT(*) AS n
        FROM licenses WHERE created_at >= $1
        GROUP BY day ORDER BY day
    `, [since]),
    activatedSeries: since => all(`
        SELECT ${DAY_SQL('activated_at')} AS day, COUNT(*) AS n
        FROM licenses WHERE activated_at IS NOT NULL AND activated_at >= $1
        GROUP BY day ORDER BY day
    `, [since]),

    recentEvents: limit => all(`
        SELECT id, key, event, machine_id, detail, created_at
        FROM license_events ORDER BY created_at DESC, id DESC LIMIT $1
    `, [limit]),

    logEvent: (key, event, machineId, ip, detail, createdAt) => run(`
        INSERT INTO license_events(key, event, machine_id, ip, detail, created_at)
        VALUES ($1, $2, $3, $4, $5, $6)
    `, [key, event, machineId, ip, detail, createdAt]),
};

export function nowSec() { return Math.floor(Date.now() / 1000); }
