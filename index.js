// --- Core & setup ---
const fastify = require('fastify')({ logger: true });
const cors = require('@fastify/cors');

// Env
const OPENAI_API_KEY = process.env.OPENAI_API_KEY || '';
const OPENAI_ENDPOINT = process.env.OPENAI_ENDPOINT || 'https://api.openai.com';
const USE_OPENAI = String(process.env.USE_OPENAI || '').toLowerCase() === 'true';

// Limbi suportate (RO, EN + primele 10 cele mai vorbite + IT)
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

// --- App bootstrap ---
async function build() {
  // CORS pentru acces din Flutter / browser
  await fastify.register(cors, { origin: true });

  // --- Helpers ---
  const localQuotes = [
    { id: 1, text: 'Succesul nu este final, eșecul nu este fatal: curajul de a continua contează.', author: 'W. Churchill', lang: 'ro' },
    { id: 2, text: 'Nu judeca fiecare zi după recolta pe care o culegi, ci după semințele pe care le plantezi.', author: 'R. L. Stevenson', lang: 'ro' },
    { id: 3, text: 'The only way to do great work is to love what you do.', author: 'Steve Jobs', lang: 'en' },
    { id: 4, text: 'Whether you think you can or you think you can’t, you’re right.', author: 'Henry Ford', lang: 'en' }
  ];

  function pickLocal(lang) {
    const pool = lang ? localQuotes.filter(q => q.lang === lang) : localQuotes;
    return pool[Math.floor(Math.random() * pool.length)];
  }

  // ——— AI: traducere citat (cu fallback) ———
  async function translateQuote({ text, author, targetLang }) {
    if (!USE_OPENAI || !OPENAI_API_KEY) {
      return { text: `[UNTRANSLATED] ${text}`, author, lang: targetLang };
    }

    const system = 'You are a translator. Return STRICT JSON {"text": string, "author": string, "lang": string}. Only translate the quote text, keep author as-is. No emojis.';
    const user = `Translate the following quote into language code "${targetLang}".\nQUOTE_TEXT: ${text}\nAUTHOR: ${author}\nReturn JSON only.`;

    try {
      const r = await fetch(`${OPENAI_ENDPOINT}/v1/chat/completions`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${OPENAI_API_KEY}`,
          'Content-Type': 'application/json'
        },
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

      if (!r.ok) {
        return { text: `[UNTRANSLATED:${r.status}] ${text}`, author, lang: targetLang };
      }
      const data = await r.json();
      const content = data?.choices?.[0]?.message?.content || '{}';
      const parsed = JSON.parse(content);
      return {
        text: parsed.text || text,
        author: parsed.author || author,
        lang: parsed.lang || targetLang
      };
    } catch {
      return { text: `[UNTRANSLATED] ${text}`, author, lang: targetLang };
    }
  }

  // --- Health / Info ---
  fastify.get('/main', async () => {
    return { ok: true, backend: USE_OPENAI && OPENAI_API_KEY ? 'openai' : 'local' };
  });

  // --- Lista limbilor pentru UI ---
  fastify.get('/langs', async () => SUPPORTED_LANGS);

  // --- Random quote local (folosit și ca fallback) ---
  fastify.get('/quotes/random', async (request, reply) => {
    const { lang } = request.query || {};
    const q = pickLocal(lang);
    reply.header('X-Source', 'local');
    return q;
  });

  // --- Citat AI/Tradus pentru orice limbă suportată ---
  fastify.get('/v1/quote', async (request, reply) => {
    const { lang = 'en', category = 'motivation' } = request.query || {};

    // Bază pentru traducere = un citat ENG din local
    const base = pickLocal('en');

    // Dacă cerem en/ro: livrăm direct sau traducem în ro
    if (lang === 'en' || lang === 'ro') {
      reply.header('X-Source', USE_OPENAI ? 'local/ai' : 'local');
      return base.lang === lang
        ? base
        : await translateQuote({ text: base.text, author: base.author, targetLang: lang });
    }

    // Alte limbi: verificăm suportul și traducem
    const isSupported = SUPPORTED_LANGS.some(l => l.code === lang);
    if (!isSupported) {
      return reply.code(400).send({ error: `Unsupported lang '${lang}'.` });
    }

    const translated = await translateQuote({ text: base.text, author: base.author, targetLang: lang });
    reply.header('X-Source', USE_OPENAI ? 'ai-translate' : 'local-fallback');
    return { id: Date.now(), text: translated.text, author: translated.author, lang: translated.lang };
  });

  // --- AI fixer endpoint: trimite eroarea aici și primești pași de remediere ---
  fastify.post('/ai/fix', async (request, reply) => {
    const { message, stack, context } = request.body || {};

    // Dacă AI e oprit sau nu avem cheie → răspuns util fără AI
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
      const r = await fetch(`${OPENAI_ENDPOINT}/v1/chat/completions`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${OPENAI_API_KEY}`,
          'Content-Type': 'application/json'
        },
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

      const data = await r.json();

      if (!r.ok) {
        return reply.code(200).send({
          usedAI: false,
          cause: `Serviciul AI a răspuns cu status ${r.status}`,
          fix_steps: ['Verifică credit/limită la OpenAI', 'Reîncearcă în câteva secunde'],
          patch_snippet: JSON.stringify(data).slice(0, 500),
          risk_notes: 'Răspuns fallback — verifică logurile locale.'
        });
      }

      let parsed;
      try { parsed = JSON.parse(data?.choices?.[0]?.message?.content || '{}'); }
      catch { parsed = { cause: 'Nu s-a putut citi răspunsul AI.', fix_steps: ['Reîncearcă.'] }; }

      return { usedAI: true, ...parsed };
    } catch (err) {
      fastify.log.error(err);
      return reply.code(200).send({
        usedAI: false,
        cause: 'Eroare locală la apelul AI.',
        fix_steps: ['Verifică Logs în Render', 'Verifică conexiunea la api.openai.com'],
        patch_snippet: String(err).slice(0, 500),
        risk_notes: 'Ține mesajele scurte; evită date sensibile.'
      });
    }
  });

  // --- Start server ---
  try {
    await fastify.listen({ port: process.env.PORT || 3000, host: '0.0.0.0' });
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
}

build();
