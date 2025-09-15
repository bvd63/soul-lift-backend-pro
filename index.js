// --- Core & setup ---
const fastify = require('fastify')({ logger: true });
const cors = require('@fastify/cors');

// Env
const OPENAI_API_KEY = process.env.OPENAI_API_KEY || '';
const OPENAI_ENDPOINT = process.env.OPENAI_ENDPOINT || 'https://api.openai.com';
const USE_OPENAI = String(process.env.USE_OPENAI || '').toLowerCase() === 'true';

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

  // --- Health / Info ---
  fastify.get('/main', async () => {
    return { ok: true, backend: USE_OPENAI && OPENAI_API_KEY ? 'openai' : 'local' };
  });

  // --- Random quote local (folosit și ca fallback) ---
  fastify.get('/quotes/random', async (request, reply) => {
    const { lang } = request.query || {};
    const q = pickLocal(lang);
    reply.header('X-Source', 'local');
    return q;
  });

  // --- (opțional) Citit prin OpenAI, cu fallback local ---
  fastify.get('/v1/quote', async (request, reply) => {
    const { lang = 'en', category = 'motivation' } = request.query || {};

    // Dacă AI e oprit sau nu avem cheie → local imediat
    if (!USE_OPENAI || !OPENAI_API_KEY) {
      reply.header('X-Source', 'local-fallback');
      return pickLocal(lang);
    }

    const system = 'You are a concise assistant. Return a short motivational quote text only.';
    const user = `Give me one short motivational quote in language: ${lang}. Topic: ${category}. No emojis.`;

    try {
      const r = await fetch(`${OPENAI_ENDPOINT}/v1/chat/completions`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${OPENAI_API_KEY}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          model: 'gpt-4o-mini',
          temperature: 0.7,
          max_tokens: 60,
          messages: [
            { role: 'system', content: system },
            { role: 'user', content: user }
          ]
        })
      });

      // Dacă API nu răspunde OK → fallback local
      if (!r.ok) {
        fastify.log.warn({ status: r.status }, 'OpenAI not ok → fallback local');
        reply.header('X-Source', 'local-fallback');
        return pickLocal(lang);
      }

      const data = await r.json();
      const content = data?.choices?.[0]?.message?.content?.trim();
      if (!content) {
        reply.header('X-Source', 'local-fallback');
        return pickLocal(lang);
      }
      reply.header('X-Source', 'openai');
      return { id: Date.now(), text: content, author: 'AI', lang };
    } catch (err) {
      fastify.log.error(err);
      reply.header('X-Source', 'local-fallback');
      return pickLocal(lang);
    }
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
        patch_snippet: '// consultă log-urile din Render → Logs pentru detalii.'
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
          patch_snippet: JSON.stringify(data).slice(0, 500)
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
        patch_snippet: String(err).slice(0, 500)
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
