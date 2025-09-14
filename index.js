const fastify = require('fastify')({ logger: true });
const cors = require('@fastify/cors');
const helmet = require('@fastify/helmet');
const rateLimit = require('@fastify/rate-limit');

const OPENAI_API_KEY = process.env.OPENAI_API_KEY || '';
const ORIGIN = process.env.ORIGIN || '*';

async function build() {
  await fastify.register(helmet);
  await fastify.register(cors, { origin: ORIGIN });
  await fastify.register(rateLimit, { max: 60, timeWindow: '1 minute' });

  const fallback = {
    motivation: ['Un pas mic azi e începutul unui drum mare.'],
    anxiety: ['Respiră. Și asta va trece.'],
    confidence: ['Ai trecut peste multe. Ești mai puternic decât crezi.'],
    relaxation: ['Închide ochii și simte prezentul.'],
    hope: ['Soarele răsare din nou după fiecare noapte.'],
  };

  fastify.get('/health', async () => ({ ok: true, hasKey: !!OPENAI_API_KEY }));

  fastify.get('/v1/quote', async (request, reply) => {
    const q = request.query || {};
    const lang = String(q.lang || 'ro').toLowerCase();
    const category = String(q.category || 'motivation').toLowerCase();

    if (!OPENAI_API_KEY) {
      return { lang, category, text: (fallback[category] || fallback.motivation)[0] };
    }

    const prompt = `Generează un citat scurt (max 20 cuvinte) pentru categoria "${category}" în limba ${lang}. Fără autor, fără emoji.`;

    try {
      const r = await fetch('https://api.openai.com/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${OPENAI_API_KEY}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          model: 'gpt-4o-mini',
          messages: [{ role: 'user', content: prompt }],
          max_tokens: 60,
        }),
      });

      const raw = await r.text();
      if (!r.ok) {
        fastify.log.error({ status: r.status, raw }, 'OpenAI error');
        return { lang, category, text: (fallback[category] || fallback.motivation)[0] };
      }
      const data = JSON.parse(raw);
      const text = (data?.choices?.[0]?.message?.content || '').trim() || (fallback[category] || fallback.motivation)[0];
      return { lang, category, text };
    } catch (e) {
      fastify.log.error(e, 'Server error');
      return { lang, category, text: (fallback[category] || fallback.motivation)[0] };
    }
  });

  const port = Number(process.env.PORT || 3000);
  await fastify.listen({ port, host: '0.0.0.0' });
  fastify.log.info(`🚀 API ready on :${port}`);
}

build();
