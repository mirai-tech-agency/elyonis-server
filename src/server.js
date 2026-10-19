// =============================================================
// Elyonis license server -- Express + better-sqlite3.
//
// Public:
//   POST /api/license/activate    { key, machineId }
//   POST /api/license/verify      { key, machineId, token }
//   POST /api/license/deactivate  { key, machineId, token }
//
// Admin (Bearer ADMIN_TOKEN):
//   GET  /api/admin/keys
//   POST /api/admin/keys/:key/extend  { expiresAt }
//   POST /api/admin/keys/:key/revoke
//   POST /api/admin/keys/:key/reset
// =============================================================

import express from 'express';
import rateLimit from 'express-rate-limit';
import { z } from 'zod';

import { db, stmts, nowSec } from './db.js';
import { randomKey } from './keys.js';
import * as hmac from './hmac.js';

const PORT = parseInt(process.env.PORT ?? '3000', 10);
const ADMIN_TOKEN = process.env.ADMIN_TOKEN;
if (!ADMIN_TOKEN || ADMIN_TOKEN.length < 16) {
    console.error('ADMIN_TOKEN env var missing or too short (16+ chars).');
    process.exit(1);
}

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '4kb' }));

// Trust the upstream proxy (Cloudflare Tunnel) so req.ip == real client IP.
app.set('trust proxy', 1);

// ---------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------
function logEvent(key, event, machineId, ip, detail) {
    try { stmts.logEvent.run(key, event, machineId ?? null, ip ?? null,
                              detail ?? null, nowSec()); }
    catch (e) { console.error('logEvent failed:', e.message); }
}

function isExpired(lic, now) {
    return lic.type !== 'perpetual' && lic.expires_at && lic.expires_at <= now;
}

const ActivateSchema   = z.object({ key: z.string().min(10).max(40),
                                     machineId: z.string().min(8).max(128) });
const VerifySchema     = z.object({ key: z.string().min(10).max(40),
                                     machineId: z.string().min(8).max(128),
                                     token: z.string().min(20).max(2048) });
const DeactivateSchema = VerifySchema;

// ---------------------------------------------------------------
// Public endpoints
// ---------------------------------------------------------------

// Activation: tightest rate limit since this is the abuse surface.
// 5 tries / IP / 15 min keeps brute-forcing license keys infeasible
// while leaving room for the licensee to retype a key once or twice.
const activateLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5,
    standardHeaders: true, legacyHeaders: false,
    message: { error: 'too-many-attempts' } });

app.post('/api/license/activate', activateLimiter, (req, res) => {
    const parsed = ActivateSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ error: 'invalid-body' });
    const { key, machineId } = parsed.data;

    const lic = stmts.findKey.get(key);
    if (!lic) {
        logEvent(key, 'reject', machineId, req.ip, 'not-found');
        return res.status(404).json({ error: 'unknown-key' });
    }
    if (lic.status === 'revoked') {
        logEvent(key, 'reject', machineId, req.ip, 'revoked');
        return res.status(403).json({ error: 'revoked' });
    }
    const now = nowSec();
    if (isExpired(lic, now)) {
        logEvent(key, 'reject', machineId, req.ip, 'expired');
        return res.status(403).json({ error: 'expired' });
    }

    // Idempotent re-activation on the SAME machine: just refresh
    // last_verify_at and re-issue a token. Licensees re-installing
    // on the same PC shouldn't need to call /deactivate first.
    if (lic.status === 'activated') {
        if (lic.machine_id !== machineId) {
            logEvent(key, 'reject', machineId, req.ip, 'machine-mismatch');
            return res.status(409).json({ error: 'in-use-elsewhere' });
        }
        stmts.touchVerify.run(now, key, machineId);
        const token = hmac.sign({
            key, machineId, type: lic.type, pack: lic.pack,
            expiresAt: lic.expires_at, issuedAt: now, v: 1,
        });
        logEvent(key, 'activate', machineId, req.ip, 'idempotent');
        return res.json({ ok: true, token, type: lic.type, pack: lic.pack,
                          expiresAt: lic.expires_at });
    }

    // Fresh activation: pool -> activated.
    const r = stmts.activate.run(machineId, now, now, key);
    if (r.changes !== 1) {
        // Race: another concurrent /activate beat us to it.
        logEvent(key, 'reject', machineId, req.ip, 'race-lost');
        return res.status(409).json({ error: 'in-use-elsewhere' });
    }
    const token = hmac.sign({
        key, machineId, type: lic.type, pack: lic.pack,
        expiresAt: lic.expires_at, issuedAt: now, v: 1,
    });
    logEvent(key, 'activate', machineId, req.ip, 'fresh');
    return res.json({ ok: true, token, type: lic.type, pack: lic.pack,
                      expiresAt: lic.expires_at });
});

// Verify: heartbeat. Lighter rate limit -- a healthy client calls
// at most once per startup + once per N days in the background.
const verifyLimiter = rateLimit({ windowMs: 60 * 1000, max: 30,
    standardHeaders: true, legacyHeaders: false,
    message: { error: 'too-many-requests' } });

app.post('/api/license/verify', verifyLimiter, (req, res) => {
    const parsed = VerifySchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ error: 'invalid-body' });
    const { key, machineId, token } = parsed.data;

    // Reject obviously-forged tokens before touching the DB.
    const payload = hmac.verify(token);
    if (!payload || payload.key !== key || payload.machineId !== machineId) {
        logEvent(key, 'reject', machineId, req.ip, 'bad-token');
        return res.status(401).json({ error: 'bad-token' });
    }

    const lic = stmts.findKey.get(key);
    if (!lic || lic.status !== 'activated' || lic.machine_id !== machineId) {
        logEvent(key, 'reject', machineId, req.ip, 'not-activated');
        return res.status(403).json({ error: 'not-activated' });
    }
    const now = nowSec();
    if (isExpired(lic, now)) {
        logEvent(key, 'reject', machineId, req.ip, 'expired');
        return res.status(403).json({ error: 'expired' });
    }

    stmts.touchVerify.run(now, key, machineId);
    // Re-issue a fresh token so the client's offline grace period
    // restarts each successful verify.
    const newToken = hmac.sign({
        key, machineId, type: lic.type, pack: lic.pack,
        expiresAt: lic.expires_at, issuedAt: now, v: 1,
    });
    logEvent(key, 'verify', machineId, req.ip, null);
    return res.json({ ok: true, token: newToken, pack: lic.pack,
                      expiresAt: lic.expires_at });
});

app.post('/api/license/deactivate', verifyLimiter, (req, res) => {
    const parsed = DeactivateSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ error: 'invalid-body' });
    const { key, machineId, token } = parsed.data;

    const payload = hmac.verify(token);
    if (!payload || payload.key !== key || payload.machineId !== machineId) {
        logEvent(key, 'reject', machineId, req.ip, 'bad-token');
        return res.status(401).json({ error: 'bad-token' });
    }

    const r = stmts.deactivate.run(key, machineId);
    if (r.changes !== 1) {
        logEvent(key, 'reject', machineId, req.ip, 'deactivate-mismatch');
        return res.status(409).json({ error: 'not-activated-here' });
    }
    logEvent(key, 'deactivate', machineId, req.ip, null);
    return res.json({ ok: true });
});

// ---------------------------------------------------------------
// Admin
// ---------------------------------------------------------------
function requireAdmin(req, res, next) {
    const h = req.headers['authorization'] ?? '';
    const m = /^Bearer\s+(.+)$/i.exec(h);
    if (!m || m[1] !== ADMIN_TOKEN) {
        return res.status(401).json({ error: 'unauthorized' });
    }
    next();
}

// Filters are optional and default to "everything", so the pre-filter
// callers (curl, the website) keep working unchanged. `status=expired`
// is a virtual value: expiry is derived from expires_at, not stored in
// the status column.
const ListQuerySchema = z.object({
    limit:  z.coerce.number().int().min(1).max(1000).default(100),
    offset: z.coerce.number().int().min(0).default(0),
    status: z.enum(['pool', 'activated', 'revoked', 'expired']).optional(),
    type:   z.enum(['perpetual', 'subscription', 'trial']).optional(),
    pack:   z.enum(['basic', 'premium', 'pro']).optional(),
    q:      z.string().trim().min(1).max(64).optional(),
});

app.get('/api/admin/keys', requireAdmin, (req, res) => {
    const parsed = ListQuerySchema.safeParse(req.query);
    if (!parsed.success) return res.status(400).json({ error: 'invalid-query' });
    const { limit, offset, status, type, pack, q } = parsed.data;

    const where = [];
    const params = { now: nowSec() };

    if (status === 'expired') {
        where.push(`type != 'perpetual' AND expires_at IS NOT NULL AND expires_at <= @now`);
    } else if (status) {
        where.push('status = @status');
        params.status = status;
    }
    if (type) {
        where.push('type = @type');
        params.type = type;
    }
    if (pack) {
        where.push('pack = @pack');
        params.pack = pack;
    }
    if (q) {
        // Key search is case-insensitive and ignores the dashes so an
        // admin can paste "xgvjx9yy5s" or the formatted key and hit the
        // same row. Notes hold the customer email / order id.
        where.push(`(REPLACE(key,'-','') LIKE @qkey OR notes LIKE @qnotes)`);
        params.qkey   = `%${q.replace(/-/g, '').toUpperCase()}%`;
        params.qnotes = `%${q}%`;
    }

    const clause = where.length ? `WHERE ${where.join(' AND ')}` : '';
    const rows = db.prepare(`
        SELECT * FROM licenses ${clause}
        ORDER BY created_at DESC LIMIT @limit OFFSET @offset
    `).all({ ...params, limit, offset });

    // Total for the same filter set, so a paginated client knows how
    // many pages exist without walking them.
    const { total } = db.prepare(
        `SELECT COUNT(*) AS total FROM licenses ${clause}`
    ).get(params);

    res.json({ ok: true, rows, total, limit, offset });
});

// Aggregate counters + daily series for the admin dashboard. Cheap
// enough to compute per request at license scale (a handful of full
// scans over a table that stays in page cache).
app.get('/api/admin/stats', requireAdmin, (req, res) => {
    const now = nowSec();
    const day = 86400;
    const c = stmts.counts.get({
        now,
        since24h: now - day,
        since7d:  now - 7 * day,
        since30d: now - 30 * day,
    });

    // SUM() over zero rows is NULL, not 0 -- normalise so a fresh DB
    // renders as zeros rather than blanks.
    const n = (v) => v ?? 0;
    const windowStart = now - 30 * day;
    const created   = new Map(stmts.createdSeries.all(windowStart).map(r => [r.day, r.n]));
    const activated = new Map(stmts.activatedSeries.all(windowStart).map(r => [r.day, r.n]));

    // Emit every day in the window, including the empty ones, so the
    // client can render a continuous axis without filling gaps itself.
    const series = [];
    for (let i = 29; i >= 0; i--) {
        const day_ = new Date((now - i * day) * 1000).toISOString().slice(0, 10);
        series.push({
            day: day_,
            created: created.get(day_) ?? 0,
            activated: activated.get(day_) ?? 0,
        });
    }

    res.json({
        ok: true,
        generatedAt: now,
        keys: {
            total:   n(c.total),
            pool:    n(c.pool),
            revoked: n(c.revoked),
            expired: n(c.expired),
        },
        accounts: {
            // Every activated key is locked to exactly one machine, so
            // "activated" is also the end-user account count. `live`
            // excludes the ones whose subscription has run out.
            total: n(c.activated),
            live:  n(c.live_accounts),
        },
        byType: {
            perpetual:    n(c.perpetual),
            subscription: n(c.subscription),
            trial:        n(c.trial),
        },
        byPack: {
            basic:   n(c.pack_basic),
            premium: n(c.pack_premium),
            pro:     n(c.pack_pro),
        },
        recent: {
            created24h:   n(c.created_24h),
            created7d:    n(c.created_7d),
            created30d:   n(c.created_30d),
            activated7d:  n(c.activated_7d),
            activated30d: n(c.activated_30d),
        },
        series,
        events: stmts.recentEvents.all(15),
    });
});

// Create a fresh key in the pool. Called by the Elyonis website after
// a successful Stripe checkout: the website POSTs the order details,
// receives the generated key, and emails it to the customer.
//
// Body:
//   { type: 'perpetual' | 'subscription' | 'trial',
//     durationDays?: number,   // mandatory unless type === 'perpetual'
//     pack?: 'basic' | 'premium' | 'pro',  // feature set; defaults to
//                               // 'basic' (entry-level commercial pack) so
//                               // pre-pack callers keep minting valid keys
//     notes?: string }          // e.g. customer email or order ID
const AdminCreateSchema = z.object({
    type: z.enum(['perpetual', 'subscription', 'trial']),
    durationDays: z.number().int().positive().max(36500).optional(),
    pack: z.enum(['basic', 'premium', 'pro']).default('basic'),
    notes: z.string().max(256).optional(),
});

app.post('/api/admin/keys', requireAdmin, (req, res) => {
    const parsed = AdminCreateSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ error: 'invalid-body' });
    const { type, durationDays, pack, notes } = parsed.data;

    if ((type === 'subscription' || type === 'trial') && !durationDays) {
        return res.status(400).json({
            error: 'missing-duration',
            detail: 'durationDays is required for subscription / trial',
        });
    }

    const now = nowSec();
    const expiresAt = durationDays ? now + durationDays * 86400 : null;

    // Collision-retry. With a 30-char alphabet over 25 positions the
    // birthday probability of a collision at our scale is microscopic,
    // but defending against it is cheap.
    let key = null;
    for (let i = 0; i < 8; i++) {
        const candidate = randomKey();
        if (!stmts.findKey.get(candidate)) { key = candidate; break; }
    }
    if (!key) return res.status(500).json({ error: 'key-generation-failed' });

    stmts.insertKey.run(key, now, type, expiresAt, pack, notes ?? null);
    logEvent(key, 'create', null, req.ip, `admin/${type}/${pack}`);
    res.status(201).json({ ok: true, key, type, pack, expiresAt });
});

// Push a key's expiry forward. Called by the website on every paid
// Stripe renewal invoice (subscriptions). Never shortens a key: a late
// or replayed webhook can't cut a customer's remaining time. The client
// picks the new expiry up on its next /verify (token re-issued there).
const AdminExtendSchema = z.object({
    expiresAt: z.number().int().positive(),
});

app.post('/api/admin/keys/:key/extend', requireAdmin, (req, res) => {
    const parsed = AdminExtendSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ error: 'invalid-body' });
    const r = stmts.extendKey.run(parsed.data.expiresAt, req.params.key);
    if (r.changes !== 1) return res.status(404).json({ error: 'unknown-key' });
    const lic = stmts.findKey.get(req.params.key);
    logEvent(req.params.key, 'extend', null, req.ip, String(lic.expires_at));
    res.json({ ok: true, key: lic.key, expiresAt: lic.expires_at });
});

app.post('/api/admin/keys/:key/revoke', requireAdmin, (req, res) => {
    const r = stmts.revokeKey.run(req.params.key);
    if (r.changes !== 1) return res.status(404).json({ error: 'unknown-key' });
    logEvent(req.params.key, 'revoke', null, req.ip, 'admin');
    res.json({ ok: true });
});

// Force-reset (back to pool). Used when a licensee lost their old
// machine and can't /deactivate from there.
app.post('/api/admin/keys/:key/reset', requireAdmin, (req, res) => {
    const r = db.prepare(`
        UPDATE licenses
        SET status='pool', machine_id=NULL,
            activated_at=NULL, last_verify_at=NULL
        WHERE key = ? AND status != 'revoked'
    `).run(req.params.key);
    if (r.changes !== 1) return res.status(404).json({ error: 'unknown-key' });
    logEvent(req.params.key, 'reset', null, req.ip, 'admin');
    res.json({ ok: true });
});

// ---------------------------------------------------------------
// Health
// ---------------------------------------------------------------
app.get('/api/health', (_req, res) => {
    res.json({ ok: true, ts: nowSec() });
});

app.use((_req, res) => res.status(404).json({ error: 'not-found' }));

app.listen(PORT, () => {
    console.log(`elyonis-license server listening on :${PORT}`);
});
