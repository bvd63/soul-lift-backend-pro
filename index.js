// SoulLift backend — Fastify v4 (ESM)
// Features: CORS, Helmet, RateLimit, Compress, Swagger, Prometheus metrics,
// OpenAI -> DeepL fallback (DeepL ca fallback). Fără Redis/BullMQ.

// ----------------- imports
import Fastify from "fastify";
import cors from "@fastify/cors";
import helmet from "@fastify/helmet";
import rateLimit from "@fastify/rate-limit";
import compress from "@fastify/compress";
import swagger from "@fastify/swagger";
import swaggerUI from "@fastify/swagger-ui";
import metrics from "fastify-metrics";

// cache simplu în memorie (ESM)
import cache from "./src/utils/memoryCache.js";

// ----------------- utils
const isProd = process.env.NODE_ENV === "production";
const app = Fastify({ logger: { level: isProd ? "info" : "debug" } });

const bool = (v, def = false) => {
  if (v === undefined || v === null) return def;
  return ["1", "true", "yes", "on"].includes(String(v).toLowerCase());
};
const num = (v, def) => {
  const n = Number(v);
  return Number.isFinite(n) ? n : def;
};
const csv = (v) =>
  String(v || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);

// ----------------- env
const PORT = num(process.env.PORT, 3000);
const ALLOW_ORIGINS = csv(process.env.ALLOW_ORIGINS || process.env.ORIGIN);
const RATE_MAX = num(process.env.RATE_MAX, 120);
const RATE_WINDOW = num(process.env.RATE_WINDOW, 60_000);

const USE_OPENAI = bool(process.env.USE_OPENAI, true);
const OPENAI_PRIMARY = process.env.OPENAI_API_KEY || "";
const OPENAI_KEYS = [OPENAI_PRIMARY, ...csv(process.env.API_KEYS)].filter(Boolean);

const DEEPL_API_KEY = process.env.DEEPL_API_KEY || "";
const DEEPL_ENDPOINT = process.env.DEEPL_ENDPOINT || "https://api-free.deepl.com";

// ----------------- plugins
await app.register(cors, {
  origin: ALLOW_ORIGINS.length ? ALLOW_ORIGINS : true,
});
await app.register(helmet, { global: true });
await app.register(rateLimit, { max: RATE_MAX, timeWindow: RATE_WINDOW });
await app.register(compress);

await app.register(swagger, {
  openapi: {
    info: { title: "SoulLift API", version: "1.0.0" },
  },
});
await app.register(swaggerUI, { routePrefix: "/docs" });

// Prometheus metrics at /metrics
await app.register(metrics, {
  endpoint: "/metrics",
  defaultMetrics: { enabled: true },
});

// ----------------- translation services
async function translateWithOpenAI(text, targetLang) {
  if (!USE_OPENAI || !OPENAI_KEYS.length) return null;
  const key = OPENAI_KEYS[0];

  const body = {
    model: "gpt-4o-mini",
    messages: [
      { role: "system", content: "Return ONLY the translated text." },
      { role: "user", content: `Translate to ${targetLang}:\n${text}` },
    ],
    temperature: 0.2,
  };

  const res = await fetch("https://api.openai.com/v1/chat/completions", {
    method: "POST",
    headers: { Authorization: `Bearer ${key}`, "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });

  if (!res.ok) {
    const t = await res.text().catch(() => "");
    throw new Error(`OpenAI ${res.status} ${t}`.slice(0, 300));
  }
  const data = await res.json();
  return data?.choices?.[0]?.message?.content?.trim() || null;
}

async function translateWithDeepL(text, targetLang) {
  if (!DEEPL_API_KEY) return null;

  const params = new URLSearchParams({
    auth_key: DEEPL_API_KEY,
    text,
    target_lang: String(targetLang || "EN").toUpperCase(),
  });

  const res = await fetch(`${DEEPL_ENDPOINT}/v2/translate`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: params,
  });

  if (!res.ok) {
    const t = await res.text().catch(() => "");
    throw new Error(`DeepL ${res.status} ${t}`.slice(0, 300));
  }
  const data = await res.json();
  return data?.translations?.[0]?.text || null;
}

async function translateText(text, targetLang = "EN") {
  if (!text) return "";
  try {
    const a = await translateWithOpenAI(text, targetLang);
    if (a) return a;
  } catch (e) {
    app.log.warn({ err: String(e).slice(0, 200) }, "OpenAI failed; fallback DeepL");
  }
  try {
    const b = await translateWithDeepL(text, targetLang);
    if (b) return b;
  } catch (e) {
    app.log.warn({ err: String(e).slice(0, 200) }, "DeepL failed");
  }
  return text; // fallback final
}

// ----------------- routes
app.get("/", async () => ({ ok: true, name: "SoulLift", uptime: process.uptime() }));
app.get("/healthz", async () => ({ status: "ok" }));

// translate endpoint
app.post("/api/translate", async (req, rep) => {
  const body = req.body || {};
  const text = body.text ?? "";
  const target = body.target ?? "EN";
  if (!text) return rep.code(400).send({ error: "Missing 'text' in body" });

  const translated = await translateText(text, target);
  return { text, target, translated };
});

// simple quote endpoint (demo)
app.get("/api/quote", async () => {
  const quote = "Your future is created by what you do today, not tomorrow.";
  const translated = await translateText(quote, "RO");
  return { quote, translated };
});

// categories endpoint (with memory cache, TTL 10 min)
app.get("/api/categories", async () => {
  const KEY = "soul:categories:v1";
  const cached = cache.get(KEY);
  if (cached) return cached;

  const cats = [
    { id: "motivation", name: "Motivation", premium: false },
    { id: "focus", name: "Focus", premium: false },
    { id: "calm", name: "Calm", premium: false },
    { id: "gratitude", name: "Gratitude", premium: false },
  ];

  cache.set(KEY, cats, 600);
  return cats;
});

// ----------------- start
try {
  await app.listen({ port: PORT, host: "0.0.0.0" });
  app.log.info(`SoulLift listening on :${PORT}`);
} catch (err) {
  app.log.error(err);
  process.exit(1);
}
