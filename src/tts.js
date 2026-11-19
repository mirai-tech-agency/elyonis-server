// =============================================================
// Voix naturelles (ElevenLabs). SEUL endroit du projet qui connaît
// la clé du fournisseur : elle vit dans ELEVENLABS_API_KEY, côté
// serveur, et ne descend jamais dans Elyonis. Le client n'envoie
// qu'un INDICE de voix (0, 1, 2...) ; le catalogue et les
// identifiants de voix restent ici.
// =============================================================

const ENDPOINT = 'https://api.elevenlabs.io/v1/text-to-speech';

// Flash v2.5 + language_code « fr » : le forfait gratuit interdit les voix
// françaises natives, forcer la langue est ce qui réduit le plus l'accent
// anglais des voix par défaut (et Flash coûte moitié moins de crédits).
const MODEL = process.env.ELEVENLABS_MODEL ?? 'eleven_flash_v2_5';
// multilingual_v2 refuse language_code : on ne l'envoie qu'aux modèles v2.5+.
const LANGUAGE = MODEL === 'eleven_multilingual_v2' ? null : 'fr';

// MP3 22 kHz / 32 kbps : largement suffisant pour de la parole et ~4x plus
// léger que du 44 kHz, donc une lecture qui démarre plus vite sur ADSL.
const FORMAT = process.env.ELEVENLABS_FORMAT ?? 'mp3_22050_32';

// Plafond par requête. ElevenLabs refuse au-delà de ~5000 caractères sur les
// modèles v2 ; Elyonis découpe les longs textes en morceaux à la PHRASE et
// les enchaîne, donc aucun appel légitime n'arrive ici au-dessus.
export const MAX_CHARS = 4800;

// Catalogue, renseigné par la variable d'environnement TTS_VOICES :
//   [{"id":"<voice_id ElevenLabs>","name":"Léa"}, ...]
// Tant qu'elle est vide, /api/tts répond 503 et Elyonis reste sur les voix
// Windows — c'est exactement le repli prévu, pas une panne.
let cachedVoices = null;
export function voices() {
    if (cachedVoices) return cachedVoices;
    try {
        const raw = JSON.parse(process.env.TTS_VOICES ?? '[]');
        cachedVoices = Array.isArray(raw)
            ? raw.filter(v => v && typeof v.id === 'string' && typeof v.name === 'string')
                 .slice(0, 8)
            : [];
    } catch {
        console.error('TTS_VOICES is not valid JSON — natural voices disabled.');
        cachedVoices = [];
    }
    return cachedVoices;
}

export function configured() {
    return Boolean(process.env.ELEVENLABS_API_KEY) && voices().length > 0;
}

// 1..10 (l'échelle des réglages d'Elyonis) -> l'échelle du fournisseur.
function scale(v, lo, hi, dflt) {
    const n = Number(v);
    if (!Number.isFinite(n)) return dflt;
    const c = Math.min(10, Math.max(1, n));
    return lo + ((c - 1) / 9) * (hi - lo);
}

// Rend { ok, audio } ou { ok:false, error, status }. Ne jette jamais :
// l'appelant doit pouvoir répondre « repli sur les voix Windows ».
export async function synthesize({ text, voice = 0, speed = 5, tone = 5 }) {
    if (!configured()) return { ok: false, error: 'tts-not-configured', status: 503 };
    const list = voices();
    const v = list[Math.min(list.length - 1, Math.max(0, Number(voice) | 0))];

    const body = {
        text,
        model_id: MODEL,
        ...(LANGUAGE && { language_code: LANGUAGE }),
        voice_settings: {
            // « Ton » : du plus posé/neutre au plus expressif.
            stability: scale(11 - tone, 0.25, 0.75, 0.5),
            similarity_boost: 0.8,
            style: scale(tone, 0.0, 0.6, 0.3),
            speed: scale(speed, 0.75, 1.2, 1.0),
        },
    };

    // 30 s : une page entière de texte prend quelques secondes à synthétiser,
    // mais une requête qui traîne doit rendre la main pour basculer sur SAPI.
    const ac = new AbortController();
    const timer = setTimeout(() => ac.abort(), 30_000);
    try {
        const r = await fetch(
            `${ENDPOINT}/${encodeURIComponent(v.id)}?output_format=${encodeURIComponent(FORMAT)}`,
            {
                method: 'POST',
                headers: {
                    'xi-api-key': process.env.ELEVENLABS_API_KEY,
                    'Content-Type': 'application/json',
                    'Accept': 'audio/mpeg',
                },
                body: JSON.stringify(body),
                signal: ac.signal,
            });
        if (!r.ok) {
            // Le corps d'erreur du fournisseur peut contenir des détails de
            // compte : il va au journal, jamais au client.
            console.error('elevenlabs', r.status, (await r.text()).slice(0, 300));
            return { ok: false, error: 'tts-upstream', status: 502 };
        }
        return { ok: true, audio: Buffer.from(await r.arrayBuffer()) };
    } catch (e) {
        console.error('elevenlabs call failed:', e.message);
        return { ok: false, error: 'tts-upstream', status: 502 };
    } finally {
        clearTimeout(timer);
    }
}
