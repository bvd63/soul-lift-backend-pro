const fastify = require('fastify')({ logger: true, bodyLimit: 32 * 1024, connectionTimeout: 10_000 });
const cors = require('@fastify/cors');
const helmet = require('@fastify/helmet');
const rateLimit = require('@fastify/rate-limit');
const compress = require('@fastify/compress');
const swagger = require('@fastify/swagger');
const swaggerUI = require('@fastify/swagger-ui');
const fastifyMetrics = require('fastify-metrics');
const Sentry = require('@sentry/node');
const { Queue, Worker } = require('bullmq');
const IORedis = require('ioredis');
const crypto = require('crypto');

// Env
const OPENAI_API_KEY = process.env.OPENAI_API_KEY || '';
const OPENAI_ENDPOINT = process.env.OPENAI_ENDPOINT || 'https://api.openai.com';
const DEEPL_API_KEY = process.env.DEEPL_API_KEY || '';
const DEEPL_ENDPOINT = process.env.DEEPL_ENDPOINT || 'https://api-free.deepl.com'; // sau https://api.deepl.com
const USE_OPENAI = String(process.env.USE_OPENAI || '').toLowerCase() === 'true';
const USE_QUEUE = String(process.env.USE_QUEUE || '').toLowerCase() === 'true';
const REDIS_URL = process.env.REDIS_URL || '';
const RATE_MAX = Number(process.env.RATE_MAX || 100);
const RATE_WINDOW = process.env.RATE_WINDOW || '1 minute';
const ALLOW_ORIGINS = (process.env.ALLOW_ORIGINS || '*').split(',').map(s => s.trim()).filter(Boolean);
const SENTRY_DSN = process.env.SENTRY_DSN || '';
const API_KEYS = (process.env.API_KEYS || '').split(',').map(s => s.trim()).filter(Boolean);

// Sentry
if (SENTRY_DSN) {
  Sentry.init({ dsn: SENTRY_DSN, tracesSampleRate: 0.1 });
  fastify.addHook('onError', async (req, reply, err) => {
    Sentry.captureException(err, { tags: { route: req.routerPath || 'unknown' }, extra: { method: req.method, url: req.url, id: req.id } });
  });
}

// Redis
const redis = REDIS_URL ? new IORedis(REDIS_URL) : null;

// Limbi
const SUPPORTED_LANGS = [
  { code: 'ro', name: 'Romanian' }, { code: 'en', name: 'English' }, { code: 'zh', name: 'Chinese' },
  { code: 'es', name: 'Spanish' }, { code: 'hi', name: 'Hindi' }, { code: 'ar', name: 'Arabic' },
  { code: 'bn', name: 'Bengali' }, { code: 'pt', name: 'Portuguese' }, { code: 'ru', name: 'Russian' },
  { code: 'fr', name: 'French' }, { code: 'de', name: 'German' }, { code: 'ja', name: 'Japanese' }, { code: 'it', name: 'Italian' }
];

// DeepL target map (doar limbile suportate de DeepL)
const DEEPL_MAP = {
  en: 'EN', fr: 'FR', de: 'DE', es: 'ES', it: 'IT', pt: 'PT-PT', 'pt-br': 'PT-BR',
  nl: 'NL', pl: 'PL', ru: 'RU', ro: 'RO', bg: 'BG', cs: 'CS', da: 'DA', el: 'EL',
  et: 'ET', fi: 'FI', hu: 'HU', id: 'ID', ja: 'JA', ko: 'KO', lt: 'LT', lv: 'LV',
  nb: 'NB', sk: 'SK', sl: 'SL', sv: 'SV', tr: 'TR', uk: 'UK', zh: 'ZH'
};

// Fallback quotes
const localQuotes = [
  { id: 1, text: 'Succesul nu este final, eșecul nu este fatal: curajul de a continua contează.', author: 'W. Churchill', lang: 'ro' },
  { id: 2, text: 'Nu judeca fiecare zi după recolta pe care o culegi, ci după semințele pe care le plantezi.', author: 'R. L. Stevenson', lang: 'ro' },
  { id: 3, text: 'The only way to do great work is to love what you do.', author: 'Steve Jobs', lang: 'en' },
  { id: 4, text: 'Whether you think you can or you think you can’t, you’re right.', author: 'Henry Ford', lang: 'en' }
];

// Utils
function pickLocal(lang) { const pool = lang ? localQuotes.filter(q => q.lang === lang) : localQuotes; return pool[Math.floor(Math.random() * pool.length)]; }
function etag(obj){ return '"' + crypto.createHash('sha1').update(JSON.stringify(obj)).digest('hex') + '"'; }
async function sleep(ms){ return new Promise(r=>setTimeout(r, ms)); }
async function withBackoff(op, tries=3, base=200){ let last; for(let i=0;i<tries;i++){ try{return await op();}catch(e){ last=e; if((e?.status||0)!==429) break; await sleep(base*Math.pow(2,i)); } } throw last; }

// Cache traduceri (Redis + memorie)
const tCache = new Map();
async function getCached(k){ return redis ? JSON.parse(await redis.get(k) || 'null') : tCache.get(k); }
async function setCached(k,v,ms=30*24*3600*1000){ if(redis) await redis.set(k, JSON.stringify(v), 'PX', ms); else tCache.set(k,v); }

// Provider: OpenAI
async function translateWithOpenAI({ text, author, targetLang }) {
  if (!USE_OPENAI || !OPENAI_API_KEY) throw new Error('openai_disabled');
  const system = 'You are a translator. Return STRICT JSON {"text": string, "author": string, "lang": string}. Only translate text, keep author.';
  const user = `Translate into "${targetLang}": ${text} (author: ${author})`;
  const j = await withBackoff(async () => {
    const r = await fetch(`${OPENAI_ENDPOINT}/v1/chat/completions`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${OPENAI_API_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ model: 'gpt-4o-mini', temperature: 0.2, messages: [{ role:'system', content: system }, { role:'user', content: user }], response_format: { type:'json_object' } })
    });
    const jj = await r.json();
    if (!r.ok) throw Object.assign(new Error('openai_not_ok'), { status: r.status, body: jj });
    return jj;
  });
  let parsed = {};
  try { parsed = JSON.parse(j?.choices?.[0]?.message?.content || '{}'); } catch {}
  return { text: parsed.text || text, author, lang: targetLang, _provider: 'openai' };
}

// Provider: DeepL
async function translateWithDeepL({ text, author, targetLang }) {
  if (!DEEPL_API_KEY) throw new Error('deepl_disabled');
  const t = DEEPL_MAP[targetLang];
  if (!t) throw new Error('deepl_lang_unsupported');
  const params = new URLSearchParams({ text, target_lang: t });
  const r = await fetch(`${DEEPL_ENDPOINT}/v2/translate`, {
    method: 'POST',
    headers: { 'Authorization': `DeepL-Auth-Key ${DEEPL_API_KEY}`, 'Content-Type': 'application/x-www-form-urlencoded' },
    body: params
  });
  const j = await r.json();
  if (!r.ok || !j.translations || !j.translations[0]?.text) throw new Error('deepl_not_ok');
  return { text: j.translations[0].text, author, lang: targetLang, _provider: 'deepl' };
}

// Multi-provider translate: OpenAI → DeepL → local
async function translateQuote({ text, author, targetLang }) {
  const key = `t:${targetLang}:${text}`;
  const cached = await getCached(key);
  if (cached) return { ...cached, author };

  // 1) OpenAI
  try {
    const res = await translateWithOpenAI({ text, author, targetLang });
    await setCached(key, res);
    return res;
  } catch {}

  // 2) DeepL
  try {
    const res = await translateWithDeepL({ text, author, targetLang });
    await setCached(key, res);
    return res;
  } catch {}

  // 3) Local
  const res = { text: `[UNTRANSLATED] ${text}`, author, lang: targetLang, _provider: 'local' };
  await setCached(key, res);
  return res;
}

// BullMQ queue
let translateQueue = null;
if (USE_QUEUE && redis) {
  translateQueue = new Queue('translations', { connection: redis });
  new Worker('translations', async job => translateQuote(job.data), { connection: redis });
}

// API key middleware
fastify.addHook('onRequest', (req, reply, done) => {
  if (!API_KEYS.length) return done();
  const given = req.headers['x-api-key'];
  if (!given || !API_KEYS.includes(given)) return reply.code(401).send({ code:'UNAUTH', message:'Invalid API key' });
  done();
});

// App
async function build() {
  await fastify.register(helmet);
  await fastify.register(cors, { origin: ALLOW_ORIGINS, methods: ['GET','POST','OPTIONS'] });
  await fastify.register(compress);
  await fastify.register(rateLimit, { max: RATE_MAX, timeWindow: RATE_WINDOW, keyGenerator: req => req.headers['x-api-key'] || req.ip });
  await fastify.register(fastifyMetrics, { endpoint: '/metrics', defaultMetrics: true });
  await fastify.register(swagger, { openapi: { info: { title: 'SoulLift API', version: '3.1.0' } } });
  await fastify.register(swaggerUI, { routePrefix: '/docs', uiConfig: { docExpansion: 'list' } });

  fastify.get('/health', async () => ({ ok: true }));
  fastify.get('/ready', async () => ({ deps: { openaiConfigured: !!OPENAI_API_KEY, deeplConfigured: !!DEEPL_API_KEY, queue: !!translateQueue } }));
  fastify.get('/langs', async () => SUPPORTED_LANGS);

  fastify.get('/quotes/random', async (req, reply) => {
    const { lang } = req.query || {};
    const q = pickLocal(lang);
    reply.header('X-Source', 'local');
    return q;
  });

  fastify.get('/v1/quote', async (req, reply) => {
    const rawPref = req.headers['accept-language']?.split(',')[0]?.slice(0,2);
    const { lang = rawPref || 'en', category = 'motivation' } = req.query || {};
    if (!SUPPORTED_LANGS.some(l => l.code === lang)) return reply.code(400).send({ code:'BAD_LANG', message:`Unsupported lang '${lang}'` });

    const base = pickLocal('en');
    let out;
    if (translateQueue) {
      const job = await translateQueue.add('translate', { text: base.text, author: base.author, targetLang: lang });
      out = await job.waitUntilFinished();
    } else {
      out = (lang === 'en') ? base : await translateQuote({ text: base.text, author: base.author, targetLang: lang });
    }

    const body = { id: Date.now(), text: out.text, author: out.author, lang, category, provider: out._provider || (USE_OPENAI ? 'openai' : DEEPL_API_KEY ? 'deepl' : 'local') };
    const tag = etag({ text: body.text, lang: body.lang });
    if (req.headers['if-none-match'] === tag) return reply.code(304).send();
    reply.header('ETag', tag);
    reply.header('X-Source', body.provider);
    return body;
  });

  // AI fixer cu Idempotency-Key
  const fixCache = new Map();
  fastify.post('/ai/fix', async (req, reply) => {
    const idemKey = req.headers['idempotency-key'];
    if (idemKey && fixCache.has(idemKey)) return fixCache.get(idemKey);

    const { message, stack, context } = req.body || {};
    if (!message) return reply.code(400).send({ code:'BAD_REQ', message:'Missing message' });

    if (!USE_OPENAI || !OPENAI_API_KEY) {
      const resp = { usedAI:false, cause:'AI dezactivat', fix_steps:['Setează USE_OPENAI=true și OPENAI_API_KEY'], patch_snippet:'', risk_notes:'-' };
      if (idemKey) fixCache.set(idemKey, resp);
      return resp;
    }

    const system = 'You are a senior engineer. Return JSON { "cause": string, "fix_steps": string[], "patch_snippet": string, "risk_notes": string }. Language: Romanian.';
    const user = `Error: ${message}\nStack: ${stack||''}\nContext: ${JSON.stringify(context||{})}`;

    try {
      const r = await fetch(`${OPENAI_ENDPOINT}/v1/chat/completions`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${OPENAI_API_KEY}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model: 'gpt-4o-mini',
          temperature: 0.2,
          messages: [{ role: 'system', content: system }, { role: 'user', content: user }],
          response_format: { type: 'json_object' }
        })
      });
      const j = await r.json();
      let parsed; try { parsed = JSON.parse(j?.choices?.[0]?.message?.content || '{}'); } catch { parsed = { cause:'Parse error', fix_steps:['Reîncearcă'] }; }
      const resp = { usedAI:true, ...parsed };
      if (idemKey) fixCache.set(idemKey, resp);
      return resp;
    } catch (err) {
      return { usedAI:false, cause:'Eroare AI', fix_steps:['Verifică loguri'], patch_snippet:String(err).slice(0,500), risk_notes:'-' };
    }
  });

  await fastify.listen({ port: process.env.PORT || 3000, host: '0.0.0.0' });
  fastify.log.info('UP: /health /ready /langs /v1/quote /ai/fix /docs /metrics');
}

build();
