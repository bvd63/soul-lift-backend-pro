// SoulLift backend (Fastify v4, ESM)
// Features: CORS, Helmet, RateLimit, Compress, Swagger, Prometheus metrics,
// OpenAI → DeepL translation fallback, optional BullMQ + Redis queue.

import Fastify from "fastify";
import cors from "@fastify/cors";
import helmet from "@fastify/helmet";
import rateLimit from "@fastify/rate-limit";
import compress from "@fastify/compress";
import swagger from "@fastify/swagger";
import swaggerUI from "@fastify/swagger-ui";
import metrics from "fastify-metrics";
import { Queue, Worker, QueueEvents } from "bullmq";
import IORedis from "ioredis";

// -------------------- helpers --------------------
const isProd = process.env.NODE_ENV === "production";

const logger =
  isProd
    ? { level: "info" }
    : {
        level: "debug",
        transport: { target: "pino-pretty", options: { translateTime: "SYS:standard" } }
      };

const app = Fastify({ logger });

const bool = (v, def = false) => {
  if (v === undefined) return def;
  return ["1", "true", "yes", "on"].includes(String(v).toLowerCase());
};

const num = (v, def) => {
  const n = Number(v);
  return Number.isFinite(n) ? n : def;
};

const asCsv = (v) =>
  String(v || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);

// -------------------- env --------------------
const PORT = num(process.env.PORT, 3000);

const ALLOW_ORIGINS =
  asCsv(process.env.ALLOW_ORIGINS || process.env.ORIGIN);
const RATE_MAX = num(process.env.RATE_MAX, 120); // req / window
const RATE_WINDOW = num(process.env.RATE_WINDOW, 60_000); // ms

const USE_OPENAI = bool(process.env.USE_OPENAI, true);
const OPENAI_PRIMARY = process.env.OPENAI_API_KEY || "";
const OPENAI_POOL = asCsv(process.env.API_KEYS);
const OPENAI_KEYS = [OPENAI_PRIMARY, ...OPENAI_POOL].filter(Boolean);

const DEEPL_API_KEY = process.env.DEEPL_API_KEY || "";
const DEEPL_ENDPOINT = process.env.DEEPL_ENDPOINT || "https://api-free.deepl.com";

const USE_QUEUE = bool(process.env.USE_QUEUE, false);
const REDIS_URL = process.env.REDIS_URL || "";

// -------------------- plugins --------------------
await app.register(cors, {
  origin: ALLOW_ORIGINS.length ? ALLOW_ORIGINS : true
});

await app.register(helmet, { global: true });
await app.register(rateLimit, {
  max: RATE_MAX,
  timeWindow: RATE_WINDOW
});
await app.register(compress);

await app.register(swagger, {
  openapi: {
    info: {
      title: "SoulLift API",
      version: "1.0.0"
    }
  }
});

await app.register(swaggerUI, {
  routePrefix: "/docs",
  uiConfig: { docExpansion: "list", deepLinking: true }
});

// Prometheus metrics at /metrics
await app.register(metrics, {
  endpoint: "/metrics",
  defaultMetrics: { enabled: true }
});

// -------------------- queue (optional) --------------------
let redis, translateQueue, queueEvents;
if (USE_QUEUE && REDIS_URL) {
  redis = new IORedis(REDIS_URL);

  translateQueue = new Queue("translate", { connection: redis });
  queueEvents = new QueueEvents("translate", { connection: redis });

  // minimal worker example (no-op translate to prove queue works)
  new Worker(
    "translate",
    async (job) => {
      app.log.info({ jobId: job.id }, "Processing job");
      // In real app you could call translateText(job.data)
      return { ok: true, echo: job.data };
    },
    { connection: redis }
  );

  queueEvents.on("completed", ({ jobId }) => {
    app.log.info({ jobId }, "Job completed");
  });
}

// -------------------- services --------------------
// OpenAI → DeepL fallback translator (simple, safe defaults)
async function translateWithOpenAI(text, targetLang) {
  if (!OPENAI_KEYS.length || !USE_OPENAI) return null;

  // Use the first available key; you could randomize for rotation
  const key = OPENAI_KEYS[0];

  // minimal chat call that asks model to return *only* the translated text
  const body = {
    model: "gpt-4o-mini",
    messages: [
      {
        role: "system",
        content:
          "You are a translation engine. Return ONLY the translated text, no explanations."
      },
      {
        role: "user",
        content: `Translate to ${targetLang}:\n${text}`
      }
    ],
    temperature: 0.2
  };

  const resp = await fetch("https://api.openai.com/v1/chat/completions", {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${key}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify(body)
  });

  if (!resp.ok) {
    const err = await resp.text().catch(() => "");
    throw new Error(`OpenAI error: ${resp.status} ${err}`.slice(0, 500));
  }

  const data = await resp.json();
  return data?.choices?.[0]?.message?.content?.trim() || null;
}

async function translateWithDeepL(text, targetLang) {
  if (!DEEPL_API_KEY) return null;

  const params = new URLSearchParams({
    auth_key: DEEPL_API_KEY,
    text,
    target_lang: String(targetLang || "EN").toUpperCase()
  });

  const resp = await fetch(`${DEEPL_ENDPOINT}/v2/translate`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: params
  });

  if (!resp.ok) {
    const err = await resp.text().catch(() => "");
    throw new Error(`DeepL error: ${resp.status} ${err}`.slice(0, 500));
  }

  const data = await resp.json();
  return data?.translations?.[0]?.text || null;
}

// Main translate (OpenAI first, DeepL fallback)
async function translateText(text, targetLang = "EN") {
  if (!text) return "";

  // Try OpenAI first
  try {
    const out = await translateWithOpenAI(text, targetLang);
    if (out) return out;
  } catch (e) {
    app.log.warn({ err: String(e).slice(0, 200) }, "OpenAI failed, falling back to DeepL");
  }

  // Fallback DeepL
  try {
    const out = await translateWithDeepL(text, targetLang);
    if (out) return out;
  } catch (e) {
    app.log.warn({ err: String(e).slice(0, 200) }, "DeepL failed");
  }

  // Final fallback: original text
  return text;
}

// -------------------- routes --------------------
app.get("/", async () => {
  return { ok: true, name: "SoulLift", uptime: process.uptime() };
});

app.get("/healthz", async () => ({ status: "ok" }));

app.post("/api/translate", async (req, rep) => {
  const body = (req.body ?? {});
  const text = body.text ?? "";
  const target = body.target ?? "EN";

  if (!text) {
    return rep.code(400).send({ error: "Missing 'text' in body" });
  }
  const translated = await translateText(text, target);
  return { text, target, translated };
});

app.get("/api/quote", async () => {
  // Placeholder endpoint – in app reală vei extrage din DB/AI.
  const quote = "Your future is created by what you do today, not tomorrow.";
  const translated = await translateText(quote, "RO");
  return { quote, translated };
});

// Optional queue test
app.post("/api/queue/test", async (req, rep) => {
  if (!translateQueue) return rep.code(503).send({ error: "Queue not enabled" });
  const payload = { when: Date.now(), sample: "hello" };
  const job = await translateQueue.add("sample", payload, { removeOnComplete: true, removeOnFail: true });
  return { queued: true, jobId: job.id };
});

// -------------------- start --------------------
try {
  await app.listen({ port: PORT, host: "0.0.0.0" });
  app.log.info(`SoulLift listening on :${PORT}`);
} catch (err) {
  app.log.error(err);
  process.exit(1);
}
