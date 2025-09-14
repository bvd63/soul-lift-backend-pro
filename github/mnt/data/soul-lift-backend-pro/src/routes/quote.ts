import { FastifyInstance } from "fastify";
import { QuoteQuery, QuoteResponse } from "../lib/schema.js";
import { getQuoteFromOpenAI } from "../lib/openai.js";
import { cacheGet, cacheSet } from "../lib/cache.js";

const fallback: Record<string,string[]> = {
  motivation: ["Un pas mic azi e începutul unui drum mare."],
  anxiety: ["Respiră. Și asta va trece."],
  confidence: ["Ai trecut peste multe. Ești mai puternic decât crezi."],
  relaxation: ["Închide ochii și simte prezentul."],
  hope: ["Soarele răsare din nou după fiecare noapte."],
};

export default async function routes(app: FastifyInstance){
  app.get<{Querystring: {lang?: string; category?: string}}>("/v1/quote", async (req, reply) => {
    const parsed = QuoteQuery.safeParse(req.query);
    if (!parsed.success){
      return reply.code(400).send({ error: "Bad query", issues: parsed.error.issues });
    }
    const { lang, category } = parsed.data;

    const key = `${lang}:${category}`;
    const cached = cacheGet(key);
    if (cached){
      const resp: QuoteResponse = { lang, category, text: cached, cached: true };
      return reply.send(resp);
    }

    if (!process.env.OPENAI_API_KEY){
      const text = fallback[category][0];
      const resp: QuoteResponse = { lang, category, text, cached: false };
      return reply.send(resp);
    }

    const prompt = `Generează un citat scurt (max 20 cuvinte) pentru categoria "${category}" în limba ${lang}. Fără autor, fără emoji.`;

    try{
      const text = await getQuoteFromOpenAI(prompt);
      cacheSet(key, text);
      const resp: QuoteResponse = { lang, category, text, cached: false };
      return reply.send(resp);
    }catch(e){
      const text = fallback[category][0];
      const resp: QuoteResponse = { lang, category, text, cached: false };
      return reply.send(resp);
    }
  });
}
