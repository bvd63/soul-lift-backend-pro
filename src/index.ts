import Fastify from "fastify";
import cors from "@fastify/cors";
import fetch from "node-fetch";

const app = Fastify({ logger: true });

const OPENAI_API_KEY = process.env.OPENAI_API_KEY || "";
const ORIGIN = process.env.ORIGIN || "*";

await app.register(cors, { origin: ORIGIN });

const fallback: Record<string,string[]> = {
  motivation: ["Un pas mic azi e începutul unui drum mare."],
  anxiety: ["Respiră. Și asta va trece."],
  confidence: ["Ai trecut peste multe. Ești mai puternic decât crezi."],
  relaxation: ["Închide ochii și simte prezentul."],
  hope: ["Soarele răsare din nou după fiecare noapte."],
};

app.get("/health", async () => ({ ok: true, hasKey: !!OPENAI_API_KEY }));

app.get("/v1/quote", async (req: any, reply) => {
  const lang = (req.query.lang as string || "ro").toLowerCase();
  const category = (req.query.category as string || "motivation").toLowerCase();

  if (!OPENAI_API_KEY){
    return { lang, category, text: fallback[category]?.[0] ?? fallback.motivation[0] };
  }

  const prompt = `Generează un citat scurt (max 20 cuvinte) pentru categoria "${category}" în limba ${lang}. Fără autor, fără emoji.`;

  try {
    const r = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${OPENAI_API_KEY}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        model: "gpt-4o-mini",
        messages: [{ role: "user", content: prompt }],
        max_tokens: 60
      })
    });

    const raw = await r.text();
    if (!r.ok) {
      req.log.error({ status: r.status, raw }, "OpenAI error");
      return { lang, category, text: fallback[category]?.[0] ?? fallback.motivation[0] };
    }
    const data = JSON.parse(raw);
    const text = (data?.choices?.[0]?.message?.content || "").trim();
    return { lang, category, text: text || (fallback[category]?.[0] ?? fallback.motivation[0]) };
  } catch (e:any) {
    req.log.error(e, "Server error");
    return { lang, category, text: fallback[category]?.[0] ?? fallback.motivation[0] };
  }
});

const port = Number(process.env.PORT || 3000);
app.listen({ port, host: "0.0.0.0" })
  .then(() => app.log.info(`🚀 API ready on :${port}`))
  .catch((err) => {
    app.log.error(err);
    process.exit(1);
  });
