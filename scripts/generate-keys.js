// =============================================================
// Generate N license keys and dump them as CSV on stdout.
// =============================================================
//   node scripts/generate-keys.js [count] [type] [expiresAt] [notes] [--pack=X]
//
// Defaults:
//   count     = 10
//   type      = 'perpetual' | 'subscription' | 'trial'  (billing duration)
//   expiresAt = null (or unix seconds for subscription/trial)
//   notes     = empty
//   --pack    = 'basic' | 'premium' | 'pro'  (feature set) -- default 'basic',
//               same default as POST /api/admin/keys. A batch destined to
//               Premium customers MUST pass --pack=premium: the client reads
//               the pack out of the activation token and a basic key ships
//               WITHOUT voice dictation. Flag rather than a 5th positional so
//               existing invocations keep working unchanged.
//
// Example:
//   node scripts/generate-keys.js 100 perpetual
//   node scripts/generate-keys.js 25 subscription 1798761600 "Q3 2026 batch" --pack=premium
// =============================================================

import { pool, stmts, nowSec } from '../src/db.js';
import { randomKey } from '../src/keys.js';

// Pull the flag out first so it never lands in a positional slot, whatever
// its place on the command line.
const argv      = process.argv.slice(2);
const packArg   = argv.find(a => a.startsWith('--pack='));
const positional = argv.filter(a => !a.startsWith('--'));

const count     = parseInt(positional[0] ?? '10', 10);
const type      = positional[1] ?? 'perpetual';
const expiresAt = positional[2] ? parseInt(positional[2], 10) : null;
const notes     = positional[3] || null;   // '' (placeholder arg) -> null
const pack      = packArg ? packArg.slice('--pack='.length) : 'basic';

if (!['perpetual', 'subscription', 'trial'].includes(type)) {
    console.error(`Invalid type: ${type}`);
    process.exit(1);
}
if (!['basic', 'premium', 'pro'].includes(pack)) {
    console.error(`Invalid pack: ${pack} (expected basic|premium|pro)`);
    process.exit(1);
}
if ((type === 'subscription' || type === 'trial') && !expiresAt) {
    console.error(`Missing expiresAt for type ${type}`);
    process.exit(1);
}

const now = nowSec();

const fresh = [];
let tries = 0;
while (fresh.length < count && tries < count * 4) {
    tries++;
    const k = randomKey();
    if (await stmts.findKey(k)) continue;   // collision (extremely unlikely)
    fresh.push(k);
}

// All-or-nothing: a half-inserted batch is worse than none.
const client = await pool.connect();
try {
    await client.query('BEGIN');
    for (const k of fresh) await stmts.insertKey(k, now, type, expiresAt, pack, notes, client);
    await client.query('COMMIT');
} catch (e) {
    await client.query('ROLLBACK');
    throw e;
} finally {
    client.release();
}
await pool.end();

// CSV out so it's trivial to import into a spreadsheet for ops. The pack is a
// column of its own: a batch is worthless to ops if you can't tell which keys
// carry dictation.
console.log('key,type,pack,expiresAt,createdAt');
for (const k of fresh) {
    console.log(`${k},${type},${pack},${expiresAt ?? ''},${now}`);
}
console.error(`Generated ${fresh.length} keys.`);
