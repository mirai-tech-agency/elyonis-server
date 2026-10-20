// Dev-only: seed a known key into a dev DB so the running Elyonis
// (built with the default localhost:3000 + placeholder HMAC) can activate it.
// Point DATABASE_URL at a Neon dev branch, NEVER at production.
const { stmts, nowSec, pool } = await import('./src/db.js');
// Une clé par pack commercialisé : la différence Basique / Premium se teste
// côté client (la dictée vocale est fermée en Basique), il faut donc pouvoir
// activer l'un ou l'autre sans reconstruire la base.
const seeds = [
  { key: '98BCV-3MMWY-E7QNV-VHWGP-GMQXH', pack: 'premium', notes: 'dev seed premium' },
  { key: '4KJ7T-QW2ND-8XRVB-M5HCP-Z3FGY', pack: 'basic',   notes: 'dev seed basique' },
];
for (const s of seeds) {
  const existing = await stmts.findKey(s.key);
  if (existing) {
    console.log('already present:', existing.key, existing.status, existing.type,
                existing.pack);
    continue;
  }
  await stmts.insertKey(s.key, nowSec(), 'perpetual', null, s.pack, s.notes);
  console.log(`inserted perpetual pool key (${s.pack}):`, s.key);
}
await pool.end();
