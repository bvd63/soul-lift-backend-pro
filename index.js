const fastify = require('fastify')({ logger: true });
const cors = require('@fastify/cors');

const OPENAI_API_KEY = process.env.OPENAI_API_KEY || '';
const OPENAI_ENDPOINT = process.env.OPENAI_ENDPOINT || 'https://api.openai.com';

async function build() {
  await fastify.register(cors, { origin: '*' });

  const fallback = {
    ro: [
      { text: 'Nu da înapoi nici măcar în fața imposibilului.', author: 'Anonim', lang: 'ro' },
      { text: 'Învață să fii statornic în muncă.', author: 'Anonim', lang: 'ro' }
    ],
    en: [
      { text: 'Consistency is the key to success.', author: 'Anon', lang: 'en' },
      { text: 'Small steps every day build big results.', author: 'Anon', lang: 'en' }
    ]
  };

  fastify.get('/main', async () => {
    return { ok: true, backend: OPENAI_API_KEY ? 'live' : 'fallback' };
  });

  fastify.get('/v1/quote', async (request, reply) => {
    const q = request.query || {};
    const lang = (q.lang || 'en').toLowerCase();
    const category = (q.category || 'motivation').toLowerCase();

    if (!OPENAI_API_KEY) {
      const pool = fallback[lang] || fallback.en;
      return pool[0];
    }

    const prompt = `Generează un citat scurt (max 20 cuvinte) potrivit pentru ${category} în limba ${lang}. Fără autor, fără emoji.`;

    try {
      const result = await fetch(`${OPENAI_ENDPOINT}/v1/chat/completions`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${OPENAI_API_KEY}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          model: 'gpt-4o-mini',
          messages: [{ role: 'user', content: prompt }],
          max_tokens: 50,
          temperature: 0.7
        })
      });

      const data = await result.json();
      const content = data.choices?.[0]?.message?.content?.trim() || 'No response';
      return { text: content, author: 'AI', lang };
    } catch (err) {
      fastify.log.error(err);
      return reply.code(500).send({ error: 'Failed to get quote from OpenAI' });
    }
  });

  // Noua rută pentru citat random local
  fastify.get('/quotes/random', async (request, reply) => {
    const { lang } = request.query;

    const quotes = [
      { id: 1, text: 'Succesul nu este final, eșecul nu este fatal: curajul de a continua contează.', author: 'W. Churchill', lang: 'ro' },
      { id: 2, text: 'Nu judeca fiecare zi după recolta pe care o culegi, ci după semințele pe care le plantezi.', author: 'R. L. Stevenson', lang: 'ro' },
      { id: 3, text: 'The only way to do great work is to love what you do.', author: 'Steve Jobs', lang: 'en' },
      { id: 4, text: 'Whether you think you can or you think you can’t, you’re right.', author: 'Henry Ford', lang: 'en' }
    ];

    const pool = lang ? quotes.filter(q => q.lang === lang) : quotes;
    if (!pool.length) return reply.code(404).send({ error: 'No quotes for selected language.' });

    const q = pool[Math.floor(Math.random() * pool.length)];
    return q;
  });

  try {
    await fastify.listen({ port: process.env.PORT || 3000, host: '0.0.0.0' });
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
}

build();
