// --- Core & setup ---
const fastify = require('fastify')({
  logger: true,
  bodyLimit: 32 * 1024,
  connectionTimeout: 10_000
});
const cors = require('@fastify/cors');
const helmet = require('@fastify/helmet');
const rateLimit = require('@fastify/rate-limit');
const compress = require('@fastify/compress');
const swagger = require('@fastify/swagger');
const swaggerUI = require('@fastify/swagger-ui');
const metrics = require('fastify-metrics').plugin;
const Sentry = require('@sentry/node');
const { Queue, Worker } = require('bullmq');
const IORedis = require('ioredis');

// ---- Env & feature flags ----
const OPENAI_API_KEY = process.env.OPENAI_API_KEY || '';
const OPENAI_ENDPOINT = process.env.OPENAI_ENDPOINT || 'https://api.openai.com';
const USE_OPENAI  = String(process.env.USE_OPENAI || '').toLowerCase() === 'true';
const USE_QUEUE   = String(process.env.USE_QUEUE  || '').toLowerCase() === 'true';
const REDIS_URL   = process.env.REDIS_URL || '';
const RATE_MAX    = Number(process.env.RATE_MAX || 100);
const RATE_WINDOW = process.env.RATE_WINDOW || '1 minute';
const ALLOW_ORIGINS = (process.env.ALLOW_ORIGINS || '*')
  .split(',').map(s => s.trim()).filter(Boolean);
const SENTRY_DSN  = process.env.SENTRY_DSN || '';

// ---- Sentry (monitorizare erori) ----
if (SENTRY_DSN) {
  Sentry.init({ dsn: SENTRY_DSN, tracesSampleRate: 0.1 });
  fastify.addHook('onError', async (req, reply, err) => {
    Sentry.captureException(err, {
      tags: { route: req.routerPath || 'unknown' },
      extra: { method: req.method, url: req.url, id: req.id }
    });
  });
}

// ---- Limbi suportate ----
const SUPPORTED_LANGS = [
  { code: 'ro', name: 'Romanian' },
  { code: 'en', name: 'English' },
  { code: 'zh', name: 'Chinese' },
  { code: 'es', name: 'Spanish' },
  { code: 'hi', name: 'Hindi' },
  { code: 'ar', name: 'Arabic' },
  { code: 'bn', name: 'Bengali' },
  { code: 'pt', name: 'Portuguese' },
  { code: 'ru', name: 'Russian' },
  { code: 'fr', name: 'French' },
  { code: 'de', name: 'German' },
  { code: 'ja', name: 'Japanese' },
  { code: 'it', name: 'Italian' }
];

// ---- Local seed quotes (fallback & traduceri) ----
const localQuotes = [
  { id: 1, text: 'Succesul nu este final, eșecul nu este fatal: curajul de a continua contează.', author: 'W. Churchill', lang: 'ro' },
  { id: 2, text: 'Nu judeca fiecare zi după recolta pe care o culegi, ci după semințele pe care le plantezi.', author: 'R. L. Stevenson', lang: 'ro' },
  { id: 3, text: 'The only way to do great work is to love what you do.', author: 'Steve Jobs', lang: 'en' },
  { id: 4, text: 'Whether you think you can or you think you can’t, you’re right.', author: 'Henry Ford', lang: 'en' }
];

// ---- Helpers ----
function pickLocal(lang) {
  const pool = lang ? localQuotes.filter(q => q.lang === lang) : localQuotes;
  return pool[Math.floor(Math.random() * pool.length)];
}

async function sleep(ms){ return new Promise(r=>setTimeout(r, ms)); }

async function withBackoff(op, tries = 3, base = 200) {
  let last;
  for (let i = 0; i < tries; i++) {
    try { return await op(); }
    catch (e) {
      last = e;
      if ((e?.status || 0) !== 429) break; // doar pe 429 are sens backoff
      await sleep(base * Math.pow(2, i));
    }
  }
  throw last;
}

// Cache simplu pentru traduceri (reduce costuri/latenta)
const tCache = new Map(); // key: `${targetLang}|${text}`

// ——— AI: traducere citat (cu backoff + cache + fallback) ———
async function translateQuote({ text, author, targetLang }) {
  const key = `${targetLang}|${text}`;
  if (tCache.has(key)) return { ...tCache.get(key), author };

  if (!USE_OPENAI || !OPENAI_API_KEY) {
    const res = { text: `[UNTRANSLATED] ${text}`, author, lang: targetLang };
    tCache.set(key, res);
    return res;
  }

  const system = 'You are a translator. Return STRICT JSON {"text": string, "author": string, "lang": string}. Only translate the quote text, keep author as-is. No emojis.';
  const user = `Translate the following quote into language code "${targetLang}".\nQUOTE_TEXT: ${text}\nAUTHOR: ${author}\nReturn JSON only.`;

  try {
    const data = await withBackoff(async () => {
      const r = await fetch(`${OPENAI_ENDPOINT}/v1/chat/completions`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${OPENAI_API_KEY}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model: 'gpt-4o-mini',
          temperature: 0.2,
          messages: [
            { role: 'system', content: system },
            { role: 'user', content: user }
          ],
          response_format: { type: 'json_object' }
        })
      });
      const j = await r.json();
      if (!r.ok) {
        const res = { text: `[UNTRANSLATED:${r.status}] ${text}`, author, lang: targetLang };
        tCache.set(key, res);
        return res;
      }
      let parsed = {};
      try { parsed = JSON.parse(j?.choices?.[0]?.message?.content || '{}'); }
      catch { parsed = {}; }
      const res = {
        text: parsed.text || text,
        author: parsed.author || author,
        lang: parsed.lang || targetLang
      };
      tCache.set(key, res);
      return res;
    });
    return data;
  } catch {
    const res = { text: `[UNTRANSLATED] ${text}`, author, lang: targetLang };
    tCache.set(key, res);
    return res;
  }
}

// ---- Queue opțională (BullMQ) pentru traduceri async ----
let translateQueue = null;
if (USE_QUEUE && REDIS_URL) {
  try {
    const redis = new IORedis(REDIS_URL);
    translateQueue = new Queue('translations', { connection: redis });

    // Worker în același proces (ok pentru simplu). Pentru producție mare → separă.
    new Worker('translations', async job => {
      const { text, author, targetLang } = job.data;
      return await translateQuote({ text, author, targetLang });
    }, { connection: redis });
  } catch (e) {
    fastify.log.error(e, 'Redis/BullMQ init failed; queue disabled');
    translateQueue = null;
  }
}

// --- App bootstrap ---
async function build() {
  // Securitate & performanță
  await fastify.register(helmet);
  await fastify.register(cors, { origin: ALLOW_ORIGINS, methods: ['GET','POST','OPTIONS'] });
  await fastify.register(compress);
  await fastify.register(rateLimit, { max: RATE_MAX, timeWindow: RATE_WINDOW });

  // Metrics Prometheus
  await fastify.register(metrics, { endpoint: '/metrics', defaultMetrics: true });

  // OpenAPI / Swagger
  await fastify.register(swagger, {
    openapi: {
      info: { title: 'SoulLift API', version: '2.0.0' }
    }
  });
  await fastify.register(swaggerUI, { routePrefix: '/docs', uiConfig: { docExpansion: 'list' } });

  // --- Health & readiness checks ---
  fastify.get('/health', async () => ({ ok: true }));
  fastify.get('/ready', async () => ({
    deps: {
      openaiConfigured: !!OPENAI_API_KEY,
      queue: !!translateQueue
    }
  }));

  // --- Info & limbi ---
  fastify.get('/main', async () => ({ ok: true, backend: USE_OPENAI && OPENAI_API_KEY ? 'openai' : 'local' }));
  fastify.get('/langs', async () => SUPPORTED_LANGS);

  // --- Random local (fallback) ---
  fastify.get('/quotes/random', {
    schema: { querystring: { type: 'object', properties: { lang: { type: 'string' } }, additionalProperties: false } }
  }, async (request, reply) => {
    const { lang } = request.query || {};
    const q = pickLocal(lang);
    reply.header('X-Source', 'local');
    return q;
  });

  // --- Citat AI/Tradus pentru orice limbă suportată ---
  fastify.get('/v1/quote', {
    schema: {
      querystring: {
        type: 'object',
        properties: { lang: { type: 'string' }, category: { type: 'string' } },
        additionalProperties: false
      }
    }
  }, async (request, reply) => {
    // Auto-detect dacă lipsește ?lang= (din Accept-Language)
    const rawPref = request.headers['accept-language']?.split(',')[0]?.slice(0,2);
    const { lang = rawPref || 'en', category = 'motivation' } = request.query || {};

    const isSupported = SUPPORTED_LANGS.some(l => l.code === lang);
    if (!isSupported) return reply.code(400).send({ error: `Unsupported lang '${lang}'.` });

    // Bază pentru traducere = un citat ENG local
    const base = pickLocal('en');

    // Coada (dacă e activă) — procesare prin Redis
    if (translateQueue && USE_QUEUE) {
      const job = await translateQueue.add('translate', { text: base.text, author: base.author, targetLang: lang });
      const res = await job.waitUntilFinished(); // simplu (sync) pentru demo
      reply.header('X-Source', USE_OPENAI ? 'ai-translate-queue' : 'local-fallback');
      return { id: Date.now(), text: res.text, author: res.author, lang: res.lang, category };
    }

    // Direct (sync)
    if (lang === 'en') {
      reply.header('X-Source', 'local');
      return { id: Date.now(), text: base.text, author: base.author, lang, category };
    }
    if (lang === 'ro') {
      const out = await translateQuote({ text: base.text, author: base.author, targetLang: 'ro' });
      reply.header('X-Source', USE_OPENAI ? 'local/ai' : 'local');
      return { id: Date.now(), text: out.text, author: out.author, lang, category };
    }

    const translated = await translateQuote({ text: base.text, author: base.author, targetLang: lang });
    reply.header('X-Source', USE_OPENAI ? 'ai-translate' : 'local-fallback');
    return { id: Date.now(), text: translated.text, author: translated.author, lang: translated.lang, category };
  });

  // --- AI fixer endpoint: trimite eroarea și primești pași de remediere ---
  fastify.post('/ai/fix', {
    schema: {
      body: {
        type: 'object',
        properties: {
          message: { type: 'string' },
          stack: { type: 'string' },
          context: { type: ['object','string','null'] }
        },
        required: ['message'],
        additionalProperties: true
      }
    }
  }, async (request, reply) => {
    const { message, stack, context } = request.body || {};

    if (!USE_OPENAI || !OPENAI_API_KEY) {
      return {
        usedAI: false,
        cause: 'AI dezactivat (setează USE_OPENAI=true și OPENAI_API_KEY).',
        fix_steps: [
          'Deschide Render → Environment.',
          'Adaugă/editează USE_OPENAI=true și OPENAI_API_KEY.',
          'Redeploy.'
        ],
        patch_snippet: '// consultă log-urile din Render → Logs pentru detalii.',
        risk_notes: 'Nu include date sensibile în context.'
      };
    }

    const shortMsg = String(message || '').slice(0, 1000);
    const shortStack = String(stack || '').slice(0, 2000);
    const shortCtx = typeof context === 'string'
      ? context.slice(0, 1500)
      : JSON.stringify(context || {}).slice(0, 1500);

    const system = 'You are a senior full-stack engineer. Return STRICT JSON: { "cause": string, "fix_steps": string[], "patch_snippet": string, "risk_notes": string }. Be concise, actionable. Language: Romanian.';
    const user = `App error report:

MESSAGE:
${shortMsg}

STACK:
${shortStack}

CONTEXT:
${shortCtx}
`;

    try {
      const data = await withBackoff(async () => {
        const r = await fetch(`${OPENAI_ENDPOINT}/v1/chat/completions`, {
          method: 'POST',
          headers: { 'Authorization': `Bearer ${OPENAI_API_KEY}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({
            model: 'gpt-4o-mini',
            temperature: 0.2,
            messages: [
              { role: 'system', content: system },
              { role: 'user', content: user }
            ],
            response_format: { type: 'json_object' }
          })
        });
        const j = await r.json();
        if (!r.ok) {
          return {
            usedAI: false,
            cause: `Serviciul AI a răspuns cu status ${r.status}`,
            fix_steps: ['Verifică credit/limită la OpenAI', 'Reîncearcă în câteva secunde'],
            patch_snippet: JSON.stringify(j).slice(0, 500),
            risk_notes: 'Răspuns fallback — verifică logurile locale.'
          };
        }
        let parsed;
        try { parsed = JSON.parse(j?.choices?.[0]?.message?.content || '{}'); }
        catch { parsed = { cause: 'Nu s-a putut citi răspunsul AI.', fix_steps: ['Reîncearcă.'] }; }
        return { usedAI: true, ...parsed };
      });
      return data;
    } catch (err) {
      fastify.log.error(err);
      return {
        usedAI: false,
        cause: 'Eroare locală la apelul AI.',
        fix_steps: ['Verifică Logs în Render', 'Verifică conexiunea la api.openai.com'],
        patch_snippet: String(err).slice(0, 500),
        risk_notes: 'Ține mesajele scurte; evită date sensibile.'
      };
    }
  });

  // Start server
  try {
    await fastify.listen({ port: process.env.PORT || 3000, host: '0.0.0.0' });
    fastify.log.info('Docs at /docs, Metrics at /metrics');
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
}

build();
