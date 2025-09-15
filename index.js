// --- Core & setup ---
import Fastify from "fastify";
import cors from "@fastify/cors";
import compress from "@fastify/compress";
import rateLimit from "@fastify/rate-limit";
import swagger from "@fastify/swagger";
import metrics from "@fastify/metrics";
import Redis from "ioredis";
import fetch from "node-fetch";

// Env vars
const USE_OPENAI = String(process.env.USE_OPENAI || "").toLowerCase() === "true";
const USE_QUEUE = String(process.env.USE_QUEUE || "").toLowerCase() === "true";
const OPENAI_API_KEY = process.env.OPENAI_API_KEY || "";
const OPENAI_ENDPOINT = process.env.OPENAI_ENDPOINT || "https://api.openai.com";
const DEEPL_API_KEY = process.env.DEEPL_API_KEY || "";
const REDIS_URL = process.env.REDIS_URL || "";
const PORT = process.env.PORT || 3000;

// Supported languages
const SUPPORTED_LANGS = [
  "ro", "en", "es", "fr", "de", "zh", "hi", "ar",
  "pt", "bn", "ru", "ja", "it"
];

// Redis
let redis;
if (USE_QUEUE && REDIS_URL) {
  redis = new Redis(REDIS_URL, { tls: {} });
}

// Fastify instance
const fastify = Fastify({
  logger: { transport: { target: "pino-pretty" } }
});

// --- Plugins ---
await fastify.register(cors, { origin: true });
await fastify.register(compress);
await fastify.register(rateLimit, { max: 100, timeWindow: "1 minute" });
await fastify.register(swagger, { openapi: { info: { title: "SoulLift API", version: "1.0.0" } } });
await fastify.register(metrics, { endpoint: "/metrics" });

// --- Local quotes fallback ---
const localQuotes = [
  { id: 1, text: "Succesul nu este final, eșecul nu este fatal: curajul de a continua contează.", author: "W. Churchill", lang: "ro" },
  { id: 2, text: "Nu judeca fiecare zi după recolta pe care o culegi, ci după semințele pe care le plantezi.", author: "R. L. Stevenson", lang: "ro" },
  { id: 3, text: "The only way to do great work is to love what you do.", author: "Steve Jobs", lang: "en" },
  { id: 4, text: "Whether you think you can or you think you can’t, you’re right.", author: "Henry Ford", lang: "en" }
];

function pickLocal(lang) {
  const pool = lang ? localQuotes.filter(q => q.lang === lang) : localQuotes;
  return pool[Math.floor(Math.random() * pool.length)];
}

// --- Routes ---
fastify.get("/health", async () => ({ ok: true, ts: Date.now() }));

fastify.get("/ready", async () => ({
  openaiConfigured: !!OPENAI_API_KEY,
  deeplConfigured: !!DEEPL_API_KEY,
  queue: !!redis
}));

// Random local
fastify.get("/quotes/random", async (req, reply) => {
  const { lang } = req.query || {};
  const q = pickLocal(lang);
  reply.header("X-Source", "local");
  return q;
});

// AI-powered quote
fastify.get("/v1/quote", async (req, reply) => {
  const { lang = "en", category = "motivation" } = req.query || {};

  // fallback local
  if (!SUPPORTED_LANGS.includes(lang)) {
    reply.header("X-Source", "local-fallback");
    return pickLocal("en");
  }

  // Try OpenAI
  if (USE_OPENAI && OPENAI_API_KEY) {
    try {
      const r = await fetch(`${OPENAI_ENDPOINT}/v1/chat/completions`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${OPENAI_API_KEY}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          model: "gpt-4o-mini",
          temperature: 0.7,
          max_tokens: 60,
          messages: [
            { role: "system", content: "You are a concise assistant. Return a short motivational quote only." },
            { role: "user", content: `Give me one short motivational quote in ${lang}, topic: ${category}. No emojis.` }
          ]
        })
      });

      if (r.ok) {
        const data = await r.json();
        const content = data?.choices?.[0]?.message?.content?.trim();
        if (content) {
          reply.header("X-Source", "openai");
          return { id: Date.now(), text: content, author: "AI", lang };
        }
      }
    } catch (err) {
      fastify.log.error(err);
    }
  }

  // Try DeepL translation (fallback)
  if (DEEPL_API_KEY) {
    try {
      const baseQuote = pickLocal("en");
      const r = await fetch(`https://api-free.deepl.com/v2/translate`, {
        method: "POST",
        headers: {
          Authorization: `DeepL-Auth-Key ${DEEPL_API_KEY}`,
          "Content-Type": "application/x-www-form-urlencoded"
        },
        body: new URLSearchParams({ text: baseQuote.text, target_lang: lang.toUpperCase() })
      });

      if (r.ok) {
        const data = await r.json();
        const translated = data?.translations?.[0]?.text;
        if (translated) {
          reply.header("X-Source", "deepl");
          return { id: Date.now(), text: translated, author: baseQuote.author, lang };
        }
      }
    } catch (err) {
      fastify.log.error(err);
    }
  }

  // fallback local
  reply.header("X-Source", "local-fallback");
  return pickLocal(lang);
});

// AI fixer
fastify.post("/ai/fix", async (req, reply) => {
  const { message, stack, context } = req.body || {};
  if (!USE_OPENAI || !OPENAI_API_KEY) {
    return { usedAI: false, cause: "AI dezactivat", fix_steps: ["Activează USE_OPENAI și setează OPENAI_API_KEY."] };
  }
  try {
    const r = await fetch(`${OPENAI_ENDPOINT}/v1/chat/completions`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${OPENAI_API_KEY}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        model: "gpt-4o-mini",
        temperature: 0.2,
        messages: [
          { role: "system", content: "You are a senior engineer. Return JSON: {cause, fix_steps[], patch_snippet, risk_notes}." },
          { role: "user", content: `Error: ${message}\nStack: ${stack}\nContext: ${JSON.stringify(context)}` }
        ],
        response_format: { type: "json_object" }
      })
    });

    if (r.ok) {
      const data = await r.json();
      return { usedAI: true, ...(JSON.parse(data?.choices?.[0]?.message?.content || "{}")) };
    }
  } catch (err) {
    fastify.log.error(err);
  }
  return { usedAI: false, cause: "Eroare locală la AI." };
});

// --- Start server ---
try {
  await fastify.listen({ port: PORT, host: "0.0.0.0" });
  fastify.log.info(`🚀 Server running on port ${PORT}`);
} catch (err) {
  fastify.log.error(err);
  process.exit(1);
}
