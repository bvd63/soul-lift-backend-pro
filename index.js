// index.js — SoulLift backend FINAL (Postgres + Stripe + OpenAI/DeepL + FCM v1 + Sentry + AI improvements)
//
// Notes:
// - Requires environment variables set in Render: DATABASE_URL, DATABASE_SSL (optional), FIREBASE_PROJECT_ID,
//   FIREBASE_CLIENT_EMAIL, FIREBASE_PRIVATE_KEY (with \n), OPENAI_API_KEY, USE_OPENAI (optional),
//   DEEPL_API_KEY (optional), STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET, STRIPE_PRICE_ID_MONTHLY,
//   STRIPE_PRICE_ID_YEARLY, JWT_SECRET, FRONTEND_URL, SENTRY_DSN (optional), TELEGRAM_BOT_TOKEN (optional), TELEGRAM_CHAT_ID (optional)
// - Run migrate.sql once to create DB schema.
// - Safe to deploy with USE_OPENAI=false (AI features disabled).
// - Adds GET / and GET /favicon.ico to avoid noisy 404s in logs.

import Fastify from "fastify";
import cors from "@fastify/cors";
import helmet from "@fastify/helmet";
import rateLimit from "@fastify/rate-limit";
import compress from "@fastify/compress";
import swagger from "@fastify/swagger";
import swaggerUI from "@fastify/swagger-ui";
import metrics from "fastify-metrics";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import fetch from "node-fetch";
import cron from "node-cron";
import Stripe from "stripe";
import fastifyRawBody from "fastify-raw-body";
import pg from "pg";
import * as Sentry from "@sentry/node";
import fs from "fs";
import dotenv from "dotenv";
import { cleanEnv, str, bool, num } from "envalid";
import logger from "./src/utils/logger.js";
import apiRetry from "./src/utils/apiRetry.js";

// ---------- basic setup ----------
dotenv.config();
const env = cleanEnv(process.env, {
  NODE_ENV: str({ default: "development" }),
  PORT: num({ default: 3000 }),
  JWT_SECRET: str({ default: "soul-lift-secret" }),
  FRONTEND_URL: str({ default: "http://localhost:5173" }),
  USE_OPENAI: str({ default: "true" }),
  OPENAI_API_KEY: str({ default: "" }),
  DEEPL_API_KEY: str({ default: "" }),
  DEEPL_ENDPOINT: str({ default: "https://api-free.deepl.com" }),
  TELEGRAM_BOT_TOKEN: str({ default: "" }),
  TELEGRAM_CHAT_ID: str({ default: "" }),
  STRIPE_SECRET_KEY: str({ default: "" }),
  STRIPE_WEBHOOK_SECRET: str({ default: "" }),
  STRIPE_PRICE_ID_MONTHLY: str({ default: "" }),
  STRIPE_PRICE_ID_YEARLY: str({ default: "" }),
  FIREBASE_PROJECT_ID: str({ default: "" }),
  FIREBASE_CLIENT_EMAIL: str({ default: "" }),
  FIREBASE_PRIVATE_KEY: str({ default: "" }),
  SENTRY_DSN: str({ default: "" }),
  DATABASE_URL: str({ default: "" }),
  DATABASE_SSL: bool({ default: false }),
  CORS_ORIGINS: str({ default: "http://localhost:5173" })
});
const isProd = env.NODE_ENV === "production";
const app = Fastify({
  logger: { level: isProd ? "info" : "debug" },
  bodyLimit: 64 * 1024,
});

const PORT = env.PORT;
const JWT_SECRET = env.JWT_SECRET;
const FRONTEND_URL = env.FRONTEND_URL;

// Flags/keys
const USE_OPENAI = (env.USE_OPENAI || "true").toLowerCase() !== "false";
const OPENAI_KEY = env.OPENAI_API_KEY || "";
const DEEPL_KEY = env.DEEPL_API_KEY || "";
const DEEPL_ENDPOINT = env.DEEPL_ENDPOINT || "https://api-free.deepl.com";
const TELEGRAM_BOT_TOKEN = env.TELEGRAM_BOT_TOKEN || "";
const TELEGRAM_CHAT_ID = env.TELEGRAM_CHAT_ID || "";

// Stripe
const stripe = new Stripe(env.STRIPE_SECRET_KEY || "", { apiVersion: "2024-06-20" });
const STRIPE_WEBHOOK_SECRET = env.STRIPE_WEBHOOK_SECRET || "";
const STRIPE_PRICE_ID_MONTHLY = env.STRIPE_PRICE_ID_MONTHLY || "";
const STRIPE_PRICE_ID_YEARLY = env.STRIPE_PRICE_ID_YEARLY || "";

// FCM v1
const FIREBASE_PROJECT_ID = env.FIREBASE_PROJECT_ID || "";
const FIREBASE_CLIENT_EMAIL = env.FIREBASE_CLIENT_EMAIL || "";
const FIREBASE_PRIVATE_KEY = (env.FIREBASE_PRIVATE_KEY || "").replace(/\\n/g, "\n");

// Sentry
if (env.SENTRY_DSN) {
  Sentry.init({ dsn: env.SENTRY_DSN, tracesSampleRate: 0.05 });
  app.log.info("Sentry initialized");
}

// Postgres
const { Pool } = pg;

// Pentru testare locală, verificăm dacă avem DATABASE_URL
let pool;
if (env.DATABASE_URL) {
  pool = new Pool({
    connectionString: env.DATABASE_URL,
    ssl: env.DATABASE_SSL ? { rejectUnauthorized: false } : undefined,
  });
} else {
  // Pentru testare locală fără bază de date
  pool = null;
  console.log("⚠️  Rulează în modul de testare fără bază de date");
}

async function query(q, params) {
  if (!pool) {
    console.log("🔍 Query simulat:", q, params);
    return { rows: [] }; // Returnează rezultat gol pentru testare
  }
  const client = await pool.connect();
  try { return await client.query(q, params); } finally { client.release(); }
}

// utils
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const normText = (s) => (s || "").toLowerCase().replace(/\\s+/g, " ").trim();

// Folosim sistemul avansat de retry pentru apeluri API
// Folosim fetch direct în loc de fetchWithRetry pentru simplitate
const fetchWithRetry = apiRetry.fetchWithRetry;

// ---------- plugins ----------
const allowedOrigins = (env.CORS_ORIGINS || "").split(",").map(s => s.trim()).filter(Boolean);
await app.register(cors, {
  origin: (origin, cb) => {
    if (!origin) return cb(null, false);
    const ok = allowedOrigins.includes(origin);
    cb(null, ok);
  },
  credentials: true
});
await app.register(helmet, { global: true, contentSecurityPolicy: false });
await app.register(rateLimit, { global: false });

// Înregistrăm sistemul de logging avansat
await app.register(compress);
await app.register(swagger, { openapi: { info: { title: "SoulLift API", version: "10.1.0" } } });
await app.register(swaggerUI, { routePrefix: "/docs" });
await app.register(metrics, { endpoint: "/metrics", defaultMetrics: { enabled: true } });
await app.register(fastifyRawBody, { field: "rawBody", global: false, runFirst: true });
await app.register(logger.fastifyPlugin, { logLevel: isProd ? "info" : "debug" });
// Global error handler
app.setErrorHandler((err, req, rep) => {
  app.log.error({ err }, "Unhandled error");
  const status = err.statusCode || 500;
  const code = err.code || "INTERNAL_ERROR";
  rep.code(status).send({ error: "Internal error", code });
});

// ---------- schema sanity check ----------
const ensureTables = async () => {
  if (!pool) {
    console.log("📋 Crearea tabelelor omisă - modul de testare");
    return;
  }
  
  // Restul codului pentru crearea tabelelor...
  await query(`
    create table if not exists users (
      email text primary key,
      password_hash text,
      created_at timestamptz default now(),
      badges jsonb default '[]',
      streak int default 0,
      last_login date,
      subscription_status text default 'inactive',
      subscription_tier text default 'free',
      stripe_customer_id text,
      stripe_sub_id text,
      current_period_end bigint
    );
  `);
  await query(`
    create table if not exists favorites (
      email text references users(email) on delete cascade,
      quote_id text,
      created_at timestamptz default now(),
      primary key(email, quote_id)
    );
  `);
  await query(`
    create table if not exists push_tokens (
      id bigserial primary key,
      email text references users(email) on delete cascade,
      token text not null unique,
      created_at timestamptz default now()
    );
  `);
  // Preferințe notificări per utilizator
  await query(`
    create table if not exists notification_preferences (
      email text primary key references users(email) on delete cascade,
      topics jsonb default '[]',
      mute boolean default false,
      quiet_hours jsonb, -- {"start":"22:00","end":"08:00","timezone":"Europe/Bucharest"}
      updated_at timestamptz default now()
    );
  `);
  // Inbox notificări (vizibil în app)
  await query(`
    create table if not exists notifications_inbox (
      id bigserial primary key,
      email text references users(email) on delete cascade,
      title text,
      body text,
      data jsonb,
      read boolean default false,
      created_at timestamptz default now()
    );
  `);
  // Index pentru interogări rapide după email și ordine descendentă a timpului
  await query(`
    create index if not exists idx_inbox_email_created on notifications_inbox(email, created_at desc);
  `);
  await query(`
    create table if not exists ai_quotes (
      id bigserial primary key,
      text text not null,
      tags jsonb default '[]',
      score int default 0,
      embedding jsonb,
      created_at timestamptz default now()
    );
  `);
  await query(`
    create table if not exists audit_log (
      id bigserial primary key,
      ts timestamptz default now(),
      type text,
      email text,
      meta jsonb
    );
  `);
  // Index pentru filtrare rapidă după email
  await query(`
    create index if not exists idx_audit_email on audit_log(email);
  `);
};
await ensureTables();

// ---------- audit helper ----------
async function pushAudit(type, email, meta) {
  try {
    await query(`insert into audit_log(type,email,meta) values($1,$2,$3)`,
      [type, email, meta ? JSON.stringify(meta) : null]);
  } catch (e) { app.log.warn("audit error", e); }
}

// ---------- notify preferences helpers ----------
function parseTimeHM(str) {
  const [h, m] = (str || "").split(":").map(x => parseInt(x, 10));
  return isNaN(h) ? null : (h * 60 + (isNaN(m) ? 0 : m));
}
function isQuietNow(pref) {
  if (!pref || !pref.quiet_hours || !pref.quiet_hours.start || !pref.quiet_hours.end) return false;
  const now = new Date();
  const minutes = now.getHours() * 60 + now.getMinutes();
  const start = parseTimeHM(pref.quiet_hours.start);
  const end = parseTimeHM(pref.quiet_hours.end);
  if (start === null || end === null) return false;
  // Interval poate trece peste miezul nopții
  if (start <= end) {
    return minutes >= start && minutes < end;
  } else {
    return minutes >= start || minutes < end;
  }
}
async function getNotificationPrefs(email) {
  try {
    const { rows } = await query(`select topics, mute, quiet_hours from notification_preferences where email=$1`, [email]);
    if (rows[0]) return {
      topics: rows[0].topics || [],
      mute: !!rows[0].mute,
      quiet_hours: rows[0].quiet_hours || null
    };
  } catch {}
  return { topics: [], mute: false, quiet_hours: null };
}

// ---------- auth helpers ----------
function generateToken(email, exp = "1h") { return jwt.sign({ email }, JWT_SECRET, { expiresIn: exp }); }
function generateRefreshToken(email, exp = "7d") { return jwt.sign({ email, type: "refresh" }, JWT_SECRET, { expiresIn: exp }); }
async function storeRefreshToken(email, token, expiresDays = 7) {
  if (!pool) return; // test mode without DB
  const expiresAt = new Date(Date.now() + expiresDays * 24 * 3600 * 1000).toISOString();
  await query(`insert into refresh_tokens(email, token, expires_at) values($1,$2,$3)`, [email, token, expiresAt]);
}
async function revokeRefreshToken(token) {
  if (!pool) return;
  await query(`update refresh_tokens set revoked_at = now() where token=$1`, [token]);
}
async function isRefreshTokenValid(token) {
  if (!pool) {
    try { const p = jwt.verify(token, JWT_SECRET); return p?.type === "refresh"; } catch { return false; }
  }
  const { rows } = await query(`select * from refresh_tokens where token=$1`, [token]);
  const rt = rows[0];
  if (!rt) return false;
  if (rt.revoked_at) return false;
  if (rt.expires_at && new Date(rt.expires_at).getTime() < Date.now()) return false;
  try {
    const p = jwt.verify(token, JWT_SECRET);
    return p?.type === "refresh";
  } catch { return false; }
}
function authMiddleware(req, rep, done) {
  const a = req.headers.authorization;
  if (!a) return rep.code(401).send({ error: "Missing Authorization header" });
  const token = a.split(" ")[1];
  try { req.user = jwt.verify(token, JWT_SECRET); done(); }
  catch { return rep.code(401).send({ error: "Invalid token" }); }
}
function todayStr() { return new Date().toISOString().slice(0, 10); }
async function updateStreakOnLogin(email) {
  const { rows } = await query(`select last_login, streak, badges from users where email=$1`, [email]);
  const user = rows[0];
  const last = user?.last_login ? user.last_login.toISOString().slice(0, 10) : null;
  const today = todayStr();
  let streak = user?.streak || 0;
  let badges = user?.badges || [];
  if (last === today) return;
  if (!last) streak = 1;
  else {
    const prev = new Date(new Date(last).getTime() + 24 * 3600 * 1000);
    streak = (prev.toISOString().slice(0, 10) === today) ? streak + 1 : 1;
  }
  if (streak === 3 && !badges.includes("Streak 3")) badges.push("Streak 3");
  if (streak === 7 && !badges.includes("Streak 7")) badges.push("Streak 7");
  if (streak === 14 && !badges.includes("Streak 14")) badges.push("Streak 14");
  await query(`update users set streak=$2, last_login=$3, badges=$4 where email=$1`,
    [email, streak, today, JSON.stringify(badges)]);
  await pushAudit("login", email, { streak });
}

// ---------- content (static) ----------
let categories = [];
try {
  if (fs.existsSync("./categories.json")) {
    categories = JSON.parse(fs.readFileSync("./categories.json", "utf-8"));
  }
} catch { categories = []; }
let categoriesETag = null;
let categoriesLastMod = null;
function computeCategoriesMeta() {
  try {
    const stat = fs.statSync("./categories.json");
    categoriesLastMod = new Date(stat.mtime).toUTCString();
    categoriesETag = `W/"${stat.size}-${Date.parse(stat.mtime)}"`;
  } catch {
    categoriesLastMod = new Date().toUTCString();
    categoriesETag = `W/"mem-${categories.length}"`;
  }
}
computeCategoriesMeta();

const QUOTES = [
  { id: "q1", text: "Your future is created by what you do today, not tomorrow.", author: "Robert Kiyosaki", source: "Interview", year: 2001, premium: false },
  { id: "q2", text: "Success is not for the lazy.", author: "Jim Rohn", source: "Seminar", year: 1985, premium: false },
  { id: "q3", text: "Focus on progress, not perfection.", author: "Bill Gates", source: "Talk", year: 2010, premium: false },
  { id: "q4", text: "Gratitude turns what we have into enough.", author: "Aesop", source: "Fables", year: -550, premium: true },
];
const PREMIUM_COLLECTIONS = [
  { id: "stoicism", name: "Stoicism Starter", items: ["q4"] },
  { id: "deep-focus", name: "Deep Focus", items: ["q2", "q3"] },
];

// Meta pentru caching la /api/quote
let quotesLastMod = Date.now();

// ---------- AI helpers (guarded) ----------
function aiEnabled() { return USE_OPENAI && !!OPENAI_KEY; }

async function openaiChat(messages, opts = {}) {
  if (!aiEnabled()) throw new Error("OPENAI disabled");
  const body = {
    model: opts.model || "gpt-4o-mini",
    messages,
    temperature: opts.temperature ?? 0.5,
    max_tokens: opts.max_tokens ?? 150,
  };
  const res = await fetchWithRetry("https://api.openai.com/v1/chat/completions", {
    method: "POST",
    headers: { Authorization: `Bearer ${OPENAI_KEY}`, "Content-Type": "application/json" },
    body: JSON.stringify(body),
  }, 3, 400);
  const data = await res.json();
  return data?.choices?.[0]?.message?.content?.trim();
}
async function openaiEmbedding(text) {
  if (!aiEnabled()) return null;
  const res = await fetchWithRetry("https://api.openai.com/v1/embeddings", {
    method: "POST",
    headers: { Authorization: `Bearer ${OPENAI_KEY}`, "Content-Type": "application/json" },
    body: JSON.stringify({ model: "text-embedding-3-small", input: text }),
  }, 3, 400);
  const data = await res.json();
  return data?.data?.[0]?.embedding || null;
}
function cosine(a, b) {
  if (!a || !b || a.length !== b.length) return 0;
  let dp = 0, na = 0, nb = 0;
  for (let i = 0; i < a.length; i++) { dp += a[i] * b[i]; na += a[i] * a[i]; nb += b[i] * b[i]; }
  return dp / (Math.sqrt(na) * Math.sqrt(nb) + 1e-12);
}

// --- critical: generateAIQuote (missing previously) ---
async function generateAIQuote() {
  if (!aiEnabled()) throw new Error("AI disabled");
  // short prompt, English default
  const messages = [
    { role: "system", content: "Generate a short, original motivational quote (max 18 words). No author. Return ONLY the quote text." },
    { role: "user", content: "Motivation for daily progress" },
  ];
  let lastErr;
  for (let i = 0; i < 3; i++) {
    try {
      const text = await openaiChat(messages, { temperature: 0.8, max_tokens: 60 });
      const cleaned = (text || "").replace(/^\"|\"$/g, "").trim();
      if (cleaned && cleaned.length >= 8) return cleaned;
      await sleep(300 * (i + 1));
    } catch (e) { lastErr = e; await sleep(300 * (i + 1)); }
  }
  if (lastErr) throw lastErr;
  throw new Error("Failed to generate quote");
}

async function aiTagAndScore(text) {
  try {
    if (!aiEnabled()) return { tags: [], score: 0, embedding: null };

    // tags
    const promptTag = [
      { role: "system", content: "You are a classifier. Return a JSON array of short tags (no explanation)." },
      { role: "user", content: `Tag this quote: "${text}"` },
    ];
    const tagsRaw = await openaiChat(promptTag, { temperature: 0.2, max_tokens: 50 });
    let tags = [];
    try { tags = JSON.parse(tagsRaw); if (!Array.isArray(tags)) tags = [String(tagsRaw)]; }
    catch { tags = (tagsRaw || "").split(",").map(s => s.trim()).filter(Boolean); }

    // score 1-100
    const promptScore = [
      { role: "system", content: "You are a critic. Return ONLY a number from 1 to 100 representing quality/impact/originality." },
      { role: "user", content: `Rate the following quote. Return only the integer: "${text}"` },
    ];
    const scoreRaw = await openaiChat(promptScore, { temperature: 0.0, max_tokens: 10 });
    const score = parseInt((scoreRaw || "0").replace(/\\D/g, ""), 10) || 0;

    // embedding
    const embedding = await openaiEmbedding(text).catch(() => null);
    return { tags, score, embedding };
  } catch (e) {
    app.log.warn("aiTagAndScore error", e);
    return { tags: [], score: 0, embedding: null };
  }
}

async function isDuplicateByEmbedding(candidateEmbedding) {
  if (!candidateEmbedding) return false;
  const { rows } = await query(`select id, embedding from ai_quotes where embedding is not null`);
  for (const r of rows) {
    try {
      const emb = r.embedding;
      const sim = cosine(candidateEmbedding, emb);
      if (sim > 0.92) return true;
    } catch {}
  }
  return false;
}

async function generateAndStoreSingle() {
  if (!aiEnabled()) return null;
  let quote = null;
  try { quote = await generateAIQuote(); }
  catch (e) { app.log.warn("generateAIQuote err", e); return null; }

  const n = normText(quote);
  if (!n) return null;

  // OpenAI moderation (best-effort)
  try {
    const r = await fetchWithRetry("https://api.openai.com/v1/moderations", {
      method: "POST",
      headers: { Authorization: `Bearer ${OPENAI_KEY}`, "Content-Type": "application/json" },
      body: JSON.stringify({ model: "omni-moderation-latest", input: quote }),
    });
    const mod = await r.json();
    const allowed = !mod?.results?.[0]?.flagged;
    if (!allowed) return null;
  } catch (e) { app.log.warn("moderation fail", e); }

  const { tags, score, embedding } = await aiTagAndScore(quote);
  if (embedding && await isDuplicateByEmbedding(embedding)) {
    app.log.info("duplicate by embedding, skip");
    return null;
  }
  await query(`insert into ai_quotes(text,tags,score,embedding) values($1,$2,$3,$4)`,
    [quote, JSON.stringify(tags), score, JSON.stringify(embedding)]);
  await pushAudit("ai:generated", null, { quote, tags, score });
  return { text: quote, tags, score };
}

async function generateBatchStore(count = 10) {
  if (!aiEnabled()) return;
  for (let i = 0; i < count; i++) {
    try { await generateAndStoreSingle(); } catch (e) { app.log.warn("gen single err", e); }
    await sleep(1200);
  }
}

// initial fill (best-effort)
(async () => { try { await generateBatchStore(10); } catch (e) { app.log.warn("initial ai gen", e); } })();
// daily cron at 06:00 Europe/Bucharest
cron.schedule("0 6 * * *", async () => {
  try { await generateBatchStore(10); } catch (e) { app.log.warn("cron ai gen", e); }
}, { timezone: "Europe/Bucharest" });

// ---------- routes ----------

// Înregistrăm rutele pentru funcționalitățile AI avansate
// app.register(aiPersonalization, { prefix: '' });
// app.register(aiRecommendations, { prefix: '' });

// noise-free
app.get("/", async () => ({ ok: true }));
app.get("/favicon.ico", async (req, rep) => rep.code(204).send());

// health & config
app.get("/health", {
  schema: {
    tags: ['System'],
    summary: 'Health check',
    response: { 200: { type: 'object', properties: { ok: { type: 'boolean' }, ts: { type: 'integer' } } } }
  }
}, async () => ({ ok: true, ts: Date.now() }));
app.get("/healthz", {
  schema: {
    tags: ['System'],
    summary: 'Health check (alias)',
    response: { 200: { type: 'object', properties: { ok: { type: 'boolean' }, ts: { type: 'integer' } } } }
  }
}, async () => ({ ok: true, ts: Date.now() }));
app.get("/config", {
  preHandler: [(req, rep, done) => { rep.header('Sunset', 'Wed, 31 Dec 2025 00:00:00 GMT'); done(); }],
  schema: {
    tags: ['System'],
    summary: 'Runtime feature flags',
    response: {
      200: {
        type: 'object',
        properties: {
          ok: { type: 'boolean' },
          features: {
            type: 'object',
            properties: {
              openai: { type: 'boolean' },
              deepl: { type: 'boolean' },
              fcm: { type: 'boolean' },
              sentry: { type: 'boolean' },
              ai_recommendations: { type: 'boolean' }
            }
          }
        }
      }
    }
  }
}, async () => ({
  ok: true,
  features: {
    openai: aiEnabled(), deepl: Boolean(DEEPL_KEY),
    fcm: Boolean(FIREBASE_PROJECT_ID && FIREBASE_CLIENT_EMAIL && FIREBASE_PRIVATE_KEY),
    sentry: Boolean(process.env.SENTRY_DSN),
    ai_recommendations: aiEnabled(),
  },
}));

// /v1 alias for config
app.get("/v1/config", {
  schema: {
    tags: ['System'],
    summary: 'Runtime feature flags (v1)',
    response: {
      200: {
        type: 'object',
        properties: {
          ok: { type: 'boolean' },
          features: {
            type: 'object',
            properties: {
              openai: { type: 'boolean' },
              deepl: { type: 'boolean' },
              fcm: { type: 'boolean' },
              sentry: { type: 'boolean' },
              ai_recommendations: { type: 'boolean' }
            }
          }
        }
      }
    }
  }
}, async () => ({
  ok: true,
  features: {
    openai: aiEnabled(), deepl: Boolean(DEEPL_KEY),
    fcm: Boolean(FIREBASE_PROJECT_ID && FIREBASE_CLIENT_EMAIL && FIREBASE_PRIVATE_KEY),
    sentry: Boolean(process.env.SENTRY_DSN),
    ai_recommendations: aiEnabled(),
  },
}));

// languages
app.get("/api/languages", {
  schema: {
    tags: ['System'],
    summary: 'Supported languages',
    response: {
      200: {
        type: 'object',
        properties: {
          ok: { type: 'boolean' },
          languages: { type: 'array', items: { type: 'string' }, minItems: 1 }
        }
      }
    }
  }
}, async () => ({ ok: true, languages: ["EN", "RO", "FR", "DE", "ES", "IT", "PT", "RU", "JA", "ZH", "NL", "PL", "TR"] }));

// auth
app.post("/api/register", {
  schema: {
    tags: ['Auth'],
    summary: 'Înregistrare utilizator',
    body: {
      type: 'object',
      properties: {
        email: { type: 'string', format: 'email' },
        password: { type: 'string', minLength: 6, maxLength: 128 }
      },
      required: ['email', 'password']
    },
    response: {
      200: {
        type: 'object',
        properties: {
          ok: { type: 'boolean' },
          user: { type: 'object', properties: { email: { type: 'string', format: 'email' } } },
          tokens: { type: 'object', properties: { access: { type: 'string' }, refresh: { type: 'string' } } }
        }
      },
      400: { type: 'object', properties: { error: { type: 'string' } } },
      409: { type: 'object', properties: { error: { type: 'string' } } }
    }
  }
}, async (req, rep) => {
  const { email, password } = req.body || {};
  if (!email || !password) return rep.code(400).send({ error: "Email and password required." });
  const { rows } = await query(`select * from users where email=$1`, [email]);
  if (rows[0]) return rep.code(409).send({ error: "User exists" });
  const hash = await bcrypt.hash(password, 10);
  await query(`insert into users(email,password_hash,created_at) values($1,$2,now())`, [email, hash]);
  await pushAudit("register", email, null);
  const access = generateToken(email, "1h");
  const refresh = generateRefreshToken(email, "7d");
  await storeRefreshToken(email, refresh, 7);
  return { ok: true, user: { email }, tokens: { access, refresh } };
});

app.post("/api/login", {
  config: { rateLimit: { max: 10, timeWindow: '1m' } },
  schema: {
    tags: ['Auth'],
    summary: 'Autentificare utilizator',
    body: {
      type: 'object',
      properties: {
        email: { type: 'string', format: 'email' },
        password: { type: 'string', minLength: 6, maxLength: 128 },
        remember: { type: 'boolean', default: false }
      },
      required: ['email', 'password']
    },
    response: {
      200: {
        type: 'object',
        properties: {
          ok: { type: 'boolean' },
          user: { type: 'object', properties: { email: { type: 'string', format: 'email' } } },
          tokens: { type: 'object', properties: { access: { type: 'string' }, refresh: { type: 'string' } } }
        }
      },
      401: { type: 'object', properties: { error: { type: 'string' } } }
    }
  }
}, async (req, rep) => {
  const { email, password, remember = false } = req.body || {};
  if (!email || !password) return rep.code(400).send({ error: "Email and password required." });
  const { rows } = await query(`select * from users where email=$1`, [email]);
  const user = rows[0];
  if (!user || !user.password_hash) return rep.code(401).send({ error: "Invalid credentials." });
  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return rep.code(401).send({ error: "Invalid credentials." });
  await updateStreakOnLogin(email);
  await pushAudit("login", email, null);
  const access = generateToken(email, "1h");
  const refreshDays = remember ? 30 : 7;
  const refresh = generateRefreshToken(email, `${refreshDays}d`);
  await storeRefreshToken(email, refresh, refreshDays);
  return { ok: true, user: { email, badges: user.badges || [] }, tokens: { access, refresh } };
});

app.post("/api/refresh", {
  config: { rateLimit: { max: 20, timeWindow: '1m' } },
  schema: {
    tags: ['Auth'],
    summary: 'Reîmprospătare token',
    body: {
      type: 'object',
      properties: { token: { type: 'string' } },
      required: ['token']
    },
    response: {
      200: {
        type: 'object',
        properties: { ok: { type: 'boolean' }, accessToken: { type: 'string' }, refreshToken: { type: 'string' } }
      },
      400: { type: 'object', properties: { error: { type: 'string' } } },
      401: { type: 'object', properties: { error: { type: 'string' } } }
    }
  }
}, async (req, rep) => {
  const { token } = req.body || {};
  if (!token) return rep.code(400).send({ error: "Missing token" });
  const valid = await isRefreshTokenValid(token);
  if (!valid) return rep.code(401).send({ error: "Invalid refresh token" });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const access = generateToken(payload.email, "1h");
    const newRefresh = generateRefreshToken(payload.email, "7d");
    await storeRefreshToken(payload.email, newRefresh, 7);
    await revokeRefreshToken(token);
    return { ok: true, accessToken: access, refreshToken: newRefresh };
  } catch { return rep.code(401).send({ error: "Invalid refresh token" }); }
});

// categories & quotes
app.get("/api/categories", {
  preHandler: [(req, rep, done) => { rep.header('Sunset', 'Wed, 31 Dec 2025 00:00:00 GMT'); done(); }],
  schema: {
    tags: ['Content'],
    summary: 'Listează categoriile',
    response: {
      200: {
        type: 'object',
        properties: {
          ok: { type: 'boolean' },
          categories: { type: 'array', items: { type: 'object', properties: { id: { type: 'string' }, name: { type: 'string' }, premium: { type: 'boolean' } }, required: ['id','name','premium'] } }
        }
      }
    }
  }
}, async (req, rep) => {
  // Conditional GET using ETag and Last-Modified
  const inm = req.headers["if-none-match"];
  const ims = req.headers["if-modified-since"];

  if (categoriesETag && inm === categoriesETag) {
    rep.header("ETag", categoriesETag);
    if (categoriesLastMod) rep.header("Last-Modified", new Date(categoriesLastMod).toUTCString());
    rep.header("Cache-Control", "public, max-age=3600, must-revalidate");
    return rep.code(304).send();
  }
  if (categoriesLastMod && ims) {
    const since = new Date(ims).getTime();
    if (!Number.isNaN(since) && since >= categoriesLastMod) {
      if (categoriesETag) rep.header("ETag", categoriesETag);
      rep.header("Last-Modified", new Date(categoriesLastMod).toUTCString());
      rep.header("Cache-Control", "public, max-age=3600, must-revalidate");
      return rep.code(304).send();
    }
  }

  if (categoriesETag) rep.header("ETag", categoriesETag);
  if (categoriesLastMod) rep.header("Last-Modified", new Date(categoriesLastMod).toUTCString());
  rep.header("Cache-Control", "public, max-age=3600, must-revalidate");
  return { ok: true, categories };
});

// /v1 alias for categories
app.get("/v1/categories", {
  schema: {
    tags: ['Content'],
    summary: 'Listează categoriile (v1)',
    response: {
      200: {
        type: 'object',
        properties: {
          ok: { type: 'boolean' },
          categories: { type: 'array', items: { type: 'object', properties: { id: { type: 'string' }, name: { type: 'string' }, premium: { type: 'boolean' } }, required: ['id','name','premium'] } }
        }
      }
    }
  }
}, async (req, rep) => {
  const inm = req.headers["if-none-match"];
  const ims = req.headers["if-modified-since"];
  if (categoriesETag && inm === categoriesETag) {
    rep.header("ETag", categoriesETag);
    if (categoriesLastMod) rep.header("Last-Modified", new Date(categoriesLastMod).toUTCString());
    rep.header("Cache-Control", "public, max-age=3600, must-revalidate");
    return rep.code(304).send();
  }
  if (categoriesLastMod && ims) {
    const since = new Date(ims).getTime();
    if (!Number.isNaN(since) && since >= categoriesLastMod) {
      if (categoriesETag) rep.header("ETag", categoriesETag);
      rep.header("Last-Modified", new Date(categoriesLastMod).toUTCString());
      rep.header("Cache-Control", "public, max-age=3600, must-revalidate");
      return rep.code(304).send();
    }
  }
  if (categoriesETag) rep.header("ETag", categoriesETag);
  if (categoriesLastMod) rep.header("Last-Modified", new Date(categoriesLastMod).toUTCString());
  rep.header("Cache-Control", "public, max-age=3600, must-revalidate");
  return { ok: true, categories };
});
app.get("/api/quote", {
  preHandler: [(req, rep, done) => { rep.header('Sunset', 'Wed, 31 Dec 2025 00:00:00 GMT'); done(); }],
  schema: {
    tags: ['Content'],
    summary: 'Obține un citat random (respectă pro/free)',
    response: { 200: { type: 'object', properties: { ok: { type: 'boolean' }, quote: { type: 'object' } } } }
  }
}, async (req, rep) => {
  const lang = (req.query?.lang || "default").toLowerCase();
  let email = null;
  try { const a = req.headers.authorization; if (a) email = jwt.verify(a.split(" ")[1], JWT_SECRET).email; } catch {}
  let isPro = false;
  if (email) {
    const { rows } = await query(`select subscription_status from users where email=$1`, [email]);
    isPro = rows[0]?.subscription_status === "active";
  }
  const pool = QUOTES.filter(q => isPro ? true : !q.premium);
  const q = pool[Math.floor(Math.random() * pool.length)];
  await pushAudit("quote:served", email, { quoteId: q.id });
  const etag = `W/"quote-${q.id}-${lang}"`;
  const inm = req.headers["if-none-match"];
  if (inm && inm === etag) {
    rep.header("ETag", etag);
    if (quotesLastMod) rep.header("Last-Modified", new Date(quotesLastMod).toUTCString());
    rep.header("Cache-Control", "public, max-age=0, must-revalidate");
    return rep.code(304).send();
  }
  if (quotesLastMod) rep.header("Last-Modified", new Date(quotesLastMod).toUTCString());
  rep.header("ETag", etag);
  rep.header("Cache-Control", "public, max-age=0, must-revalidate");
  return { ok: true, quote: q };
});

// /v1 alias for quote
app.get("/v1/quote", {
  schema: {
    tags: ['Content'],
    summary: 'Obține un citat random (v1)',
    response: { 200: { type: 'object', properties: { ok: { type: 'boolean' }, quote: { type: 'object' } } } }
  }
}, async (req, rep) => {
  const lang = (req.query?.lang || "default").toLowerCase();
  let email = null;
  try { const a = req.headers.authorization; if (a) email = jwt.verify(a.split(" ")[1], JWT_SECRET).email; } catch {}
  let isPro = false;
  if (email) {
    const { rows } = await query(`select subscription_status from users where email=$1`, [email]);
    isPro = rows[0]?.subscription_status === "active";
  }
  const pool = QUOTES.filter(q => isPro ? true : !q.premium);
  const q = pool[Math.floor(Math.random() * pool.length)];
  await pushAudit("quote:served", email, { quoteId: q.id });
  const etag = `W/"quote-${q.id}-${lang}"`;
  const inm = req.headers["if-none-match"];
  if (inm && inm === etag) {
    rep.header("ETag", etag);
    if (quotesLastMod) rep.header("Last-Modified", new Date(quotesLastMod).toUTCString());
    rep.header("Cache-Control", "public, max-age=0, must-revalidate");
    return rep.code(304).send();
  }
  if (quotesLastMod) rep.header("Last-Modified", new Date(quotesLastMod).toUTCString());
  rep.header("ETag", etag);
  rep.header("Cache-Control", "public, max-age=0, must-revalidate");
  return { ok: true, quote: q };
});

// AI export (read-only)
app.get("/api/ai/export", {
  schema: {
    tags: ['AI'],
    summary: 'Export ultimele citate AI',
    response: {
      200: { type: 'object', properties: { ok: { type: 'boolean' }, quotes: { type: 'array' } } }
    }
  }
}, async () => {
  const { rows } = await query(`select id,text,tags,score,created_at from ai_quotes order by created_at desc limit 200`);
  return { ok: true, quotes: rows };
});

// favorites
app.post("/api/favorites/toggle", {
  preHandler: [authMiddleware],
  schema: {
    tags: ['Favorites'],
    summary: 'Comută preferința pe un citat',
    body: { type: 'object', properties: { quoteId: { type: 'integer', minimum: 1 } }, required: ['quoteId'] },
    response: { 200: { type: 'object', properties: { ok: { type: 'boolean' } } } }
  }
}, async (req, rep) => {
  const { quoteId } = req.body || {};
  if (!quoteId) return rep.code(400).send({ error: "quoteId required" });
  const email = req.user.email;
  const { rows } = await query(`select * from favorites where email=$1 and quote_id=$2`, [email, quoteId]);
  if (rows[0]) await query(`delete from favorites where email=$1 and quote_id=$2`, [email, quoteId]);
  else await query(`insert into favorites(email,quote_id) values($1,$2)`, [email, quoteId]);
  await pushAudit("favorite:toggle", email, { quoteId });
  return { ok: true };
});
app.get("/api/favorites", {
  preHandler: [authMiddleware],
  schema: {
    tags: ['Favorites'],
    summary: 'Listă preferințe utilizator',
    response: { 200: { type: 'object', properties: { ok: { type: 'boolean' }, items: { type: 'array' } } } }
  }
}, async (req) => {
  const email = req.user.email;
  const { rows } = await query(`select quote_id from favorites where email=$1`, [email]);
  return { ok: true, items: rows.map(r => QUOTES.find(q => q.id === r.quote_id)).filter(Boolean) };
});

// search quotes (static + AI) - Production Grade
app.get("/api/search", {
  schema: {
    querystring: {
      type: 'object',
      properties: {
        q: { type: 'string', minLength: 2, maxLength: 128 },
        limit: { type: 'integer', minimum: 1, maximum: 50, default: 20 },
        offset: { type: 'integer', minimum: 0, default: 0 }
      },
      required: ['q']
    },
    response: {
      200: {
        type: 'object',
        properties: {
          ok: { type: 'boolean' },
          results: { type: 'array' },
          total: { type: 'integer' },
          query: { type: 'string' },
          pagination: { type: 'object' }
        }
      }
    }
  }
}, async (req, rep) => {
  const { q, limit = 20, offset = 0 } = req.query || {};
  
  // Input validation & normalization
  const searchTerm = normalizeSearchTerm(q);
  if (!searchTerm || searchTerm.length < 2) {
    return rep.code(400).send({ error: "Query must be at least 2 characters" });
  }

  let email = null;
  try { 
    const a = req.headers.authorization; 
    if (a) email = jwt.verify(a.split(" ")[1], JWT_SECRET).email; 
  } catch {}
  
  let isPro = false;
  if (email) {
    const { rows } = await query(`select subscription_status from users where email=$1`, [email]);
    isPro = rows[0]?.subscription_status === "active";
  }

  try {
    // Collect all results for proper global pagination
    const allResults = [];

    // 1. Search static quotes
    const staticMatches = QUOTES.filter(quote => {
      if (quote.premium && !isPro) return false;
      return matchesQuery(quote, searchTerm);
    }).map(quote => ({
      ...quote,
      source_type: 'static',
      relevance_score: calculateNormalizedScore(quote, searchTerm, 'static'),
      matched_fields: getMatchedFields(quote, searchTerm),
      highlights: generateHighlights(quote.text, searchTerm)
    }));

    allResults.push(...staticMatches);

    // 2. Search AI quotes with websearch_to_tsquery
    if (pool) {
      const aiSearchQuery = `
        SELECT id, text, tags, score, created_at,
               ts_rank(to_tsvector('english', text), websearch_to_tsquery('english', $1)) as rank,
               ts_headline('english', text, websearch_to_tsquery('english', $1), 
                          'MaxWords=20, MinWords=5, ShortWord=3, HighlightAll=false, MaxFragments=2') as headline
        FROM ai_quotes 
        WHERE to_tsvector('english', text) @@ websearch_to_tsquery('english', $1)
           OR text ILIKE $2
           OR tags @> $3::jsonb
        ORDER BY rank DESC, score DESC
      `;
      
      const { rows: aiQuotes } = await query(aiSearchQuery, [
        searchTerm, 
        `%${searchTerm}%`,
        JSON.stringify([searchTerm])
      ]);

      const aiMatches = aiQuotes.map(quote => ({
        id: `ai_${quote.id}`,
        text: quote.text,
        author: "AI Generated",
        source: "SoulLift AI",
        year: new Date(quote.created_at).getFullYear(),
        premium: false,
        tags: quote.tags || [],
        score: quote.score || 0,
        source_type: 'ai',
        relevance_score: calculateNormalizedScore(quote, searchTerm, 'ai', quote.rank),
        matched_fields: getMatchedFields(quote, searchTerm),
        highlights: quote.headline || generateHighlights(quote.text, searchTerm),
        created_at: quote.created_at
      }));

      allResults.push(...aiMatches);
    }

    // 3. Remove duplicates
    const deduplicatedResults = removeDuplicates(allResults);

    // 4. Sort by normalized relevance score and apply global pagination
    const sortedResults = deduplicatedResults
      .sort((a, b) => b.relevance_score - a.relevance_score)
      .slice(parseInt(offset), parseInt(offset) + parseInt(limit));

    // 5. Log search audit
    await pushAudit("search:query", email, { 
      query: searchTerm, 
      resultsCount: sortedResults.length,
      totalFound: deduplicatedResults.length,
      isPro 
    });

    return { 
      ok: true, 
      results: sortedResults,
      total: deduplicatedResults.length,
      query: searchTerm,
      pagination: {
        limit: parseInt(limit),
        offset: parseInt(offset),
        hasMore: deduplicatedResults.length > parseInt(offset) + parseInt(limit)
      }
    };

  } catch (error) {
    app.log.error("Search error:", error);
    return rep.code(500).send({ error: "Search failed" });
  }
});

// Helper functions for enhanced search
function normalizeSearchTerm(term) {
  if (!term) return '';
  return term.trim()
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '') // Remove diacritics
    .toLowerCase()
    .substring(0, 128);
}

function matchesQuery(quote, searchTerm) {
  const text = quote.text.toLowerCase();
  const author = quote.author.toLowerCase();
  const source = quote.source?.toLowerCase() || "";
  
  return text.includes(searchTerm) || 
         author.includes(searchTerm) || 
         source.includes(searchTerm);
}

function calculateNormalizedScore(quote, searchTerm, sourceType, dbRank = 0) {
  let score = 0;
  
  if (sourceType === 'ai' && dbRank) {
    // Use PostgreSQL ts_rank as base (0-1 range typically)
    score = Math.min(dbRank, 1.0);
  } else {
    // Calculate score for static quotes
    const text = quote.text.toLowerCase();
    const author = quote.author.toLowerCase();
    const source = quote.source?.toLowerCase() || "";
    
    // Exact phrase match
    if (text.includes(searchTerm)) score += 0.4;
    if (author.includes(searchTerm)) score += 0.3;
    if (source.includes(searchTerm)) score += 0.2;
    
    // Word boundary matches (higher relevance)
    const wordBoundaryRegex = new RegExp(`\\b${searchTerm}\\b`, 'i');
    if (wordBoundaryRegex.test(quote.text)) score += 0.3;
    if (wordBoundaryRegex.test(quote.author)) score += 0.2;
    
    // Beginning of text match
    if (text.startsWith(searchTerm)) score += 0.2;
    
    // Normalize to 0-1 range
    score = Math.min(score, 1.0);
  }
  
  return score;
}

function getMatchedFields(quote, searchTerm) {
  const matched = [];
  const text = quote.text?.toLowerCase() || '';
  const author = quote.author?.toLowerCase() || '';
  const source = quote.source?.toLowerCase() || '';
  
  if (text.includes(searchTerm)) matched.push('text');
  if (author.includes(searchTerm)) matched.push('author');
  if (source.includes(searchTerm)) matched.push('source');
  if (quote.tags && Array.isArray(quote.tags)) {
    const hasTagMatch = quote.tags.some(tag => 
      tag.toLowerCase().includes(searchTerm)
    );
    if (hasTagMatch) matched.push('tags');
  }
  
  return matched;
}

function generateHighlights(text, searchTerm, maxLength = 150) {
  if (!text || !searchTerm) return text;
  
  const regex = new RegExp(`(${searchTerm})`, 'gi');
  const highlighted = text.replace(regex, '<mark>$1</mark>');
  
  // Truncate if too long, keeping highlights
  if (highlighted.length > maxLength) {
    const index = highlighted.toLowerCase().indexOf(searchTerm.toLowerCase());
    if (index !== -1) {
      const start = Math.max(0, index - 50);
      const end = Math.min(highlighted.length, start + maxLength);
      return (start > 0 ? '...' : '') + 
             highlighted.substring(start, end) + 
             (end < highlighted.length ? '...' : '');
    }
  }
  
  return highlighted;
}

function removeDuplicates(results) {
  const seen = new Set();
  return results.filter(quote => {
    const normalizedText = quote.text.trim().toLowerCase();
    if (seen.has(normalizedText)) {
      return false;
    }
    seen.add(normalizedText);
    return true;
  });
}

// translate
app.post("/api/translate", {
  schema: {
    tags: ['Utils'],
    summary: 'Tradu un text',
    body: { type: 'object', properties: { text: { type: 'string', minLength: 1 }, targetLang: { type: 'string', default: 'EN' } }, required: ['text'] },
    response: { 200: { type: 'object', properties: { ok: { type: 'boolean' }, translated: { type: 'string' } } } }
  }
}, async (req, rep) => {
  const { text, targetLang = "EN" } = req.body || {};
  if (!text) return rep.code(400).send({ error: "text required" });
  const t = await translateText(text, targetLang);
  await pushAudit("translate", null, { targetLang });
  return { ok: true, translated: t };
});

async function translateText(text, targetLang = "EN") {
  if (!text) return "";
  // OpenAI first
  try {
    if (aiEnabled()) {
      const body = {
        model: "gpt-4o-mini",
        messages: [
          { role: "system", content: "Return ONLY the translated text." },
          { role: "user", content: `Translate to ${targetLang}:\n${text}` },
        ],
        temperature: 0.2,
      };
      const r = await fetchWithRetry("https://api.openai.com/v1/chat/completions", {
        method: "POST",
        headers: { Authorization: `Bearer ${OPENAI_KEY}`, "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const data = await r.json();
      const guess = data?.choices?.[0]?.message?.content?.trim();
      if (guess) return guess;
    }
  } catch (e) { app.log.warn("openai translate fail", e); }
  // DeepL fallback
  try {
    if (DEEPL_KEY) {
      const params = new URLSearchParams({ auth_key: DEEPL_KEY, text, target_lang: targetLang.toUpperCase() });
      const r = await fetchWithRetry(`${DEEPL_ENDPOINT}/v2/translate`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: params,
      });
      const d = await r.json();
      return d?.translations?.[0]?.text || text;
    }
  } catch (e) { app.log.warn("deepl fail", e); }
  return text;
}

// ---------- Stripe billing ----------
app.post("/api/billing/checkout", {
  preHandler: [authMiddleware],
  schema: {
    tags: ['Billing'],
    summary: 'Creează sesiune de checkout Stripe',
    body: { type: 'object', properties: { plan: { type: 'string', enum: ['monthly','yearly'], default: 'monthly' } } },
    response: { 200: { type: 'object', properties: { ok: { type: 'boolean' }, url: { type: 'string', format: 'uri' } } },
               500: { type: 'object', properties: { error: { type: 'string' } } } }
  }
}, async (req, rep) => {
  const { plan = "monthly" } = req.body || {};
  const priceId = plan === "yearly" ? STRIPE_PRICE_ID_YEARLY : STRIPE_PRICE_ID_MONTHLY;
  if (!priceId) return rep.code(500).send({ error: "Price not configured." });
  const email = req.user.email;
  let { rows } = await query(`select stripe_customer_id from users where email=$1`, [email]);
  let customerId = rows[0]?.stripe_customer_id;
  if (!customerId) {
    const customer = await stripe.customers.create({ email });
    customerId = customer.id;
    await query(`update users set stripe_customer_id=$2 where email=$1`, [email, customerId]);
  }
  const session = await stripe.checkout.sessions.create({
    mode: "subscription",
    customer: customerId,
    line_items: [{ price: priceId, quantity: 1 }],
    allow_promotion_codes: true,
    success_url: `${FRONTEND_URL}/pro/success?session_id={CHECKOUT_SESSION_ID}`,
    cancel_url: `${FRONTEND_URL}/pro/cancel`,
    billing_address_collection: "auto",
  });
  await pushAudit("checkout:create", email, { plan });
  return { ok: true, url: session.url };
});

app.get("/api/billing/portal", {
  preHandler: [authMiddleware],
  schema: {
    tags: ['Billing'],
    summary: 'Stripe customer portal session',
    response: {
      200: { type: 'object', properties: { ok: { type: 'boolean' }, url: { type: 'string', format: 'uri' } } },
      400: { type: 'object', properties: { error: { type: 'string' } } }
    }
  }
}, async (req, rep) => {
  const { rows } = await query(`select stripe_customer_id from users where email=$1`, [req.user.email]);
  const customerId = rows[0]?.stripe_customer_id;
  if (!customerId) return rep.code(400).send({ error: "No Stripe customer" });
  const portal = await stripe.billingPortal.sessions.create({ customer: customerId, return_url: `${FRONTEND_URL}/account` });
  return { ok: true, url: portal.url };
});

app.route({
  method: "POST",
  url: "/api/stripe/webhook",
  config: { rawBody: true },
  schema: {
    tags: ['Billing'],
    summary: 'Stripe Webhook',
    headers: {
      type: 'object',
      properties: { 'stripe-signature': { type: 'string' } },
      required: ['stripe-signature']
    },
    response: { 200: { type: 'object', properties: { received: { type: 'boolean' } } }, 400: { type: 'object', properties: { error: { type: 'string' } } } }
  },
  handler: async (req, rep) => {
    const sig = req.headers["stripe-signature"];
    let event;
    try { event = stripe.webhooks.constructEvent(req.rawBody, sig, STRIPE_WEBHOOK_SECRET); }
    catch (e) { app.log.error("stripe webhook invalid", e); return rep.code(400).send({ error: e.message }); }

    try {
      if (event.type === "checkout.session.completed") {
        const s = event.data.object;
        const email = s.customer_email || s.customer_details?.email;
        if (email) await query(`update users set subscription_status='active', subscription_tier='pro' where email=$1`, [email]);
        await pushAudit("stripe:checkout.completed", email, { id: s.id });
      } else if (event.type === "customer.subscription.updated" || event.type === "customer.subscription.created") {
        const sub = event.data.object;
        const cust = sub.customer;
        if (cust) {
          await query(`update users set subscription_tier=$2, subscription_status=$3, stripe_sub_id=$4, current_period_end=$5 where stripe_customer_id=$1`,
            [cust, sub?.items?.data?.[0]?.price?.nickname || null, sub.status, sub.id, sub.current_period_end * 1000]);
        }
        await pushAudit("stripe:subscription.update", null, { status: sub.status });
      } else if (event.type === "customer.subscription.deleted") {
        const sub = event.data.object;
        const cust = sub.customer;
        if (cust) await query(`update users set subscription_status='canceled', subscription_tier='free' where stripe_customer_id=$1`, [cust]);
        await pushAudit("stripe:subscription.deleted", null, { id: sub.id });
      }
    } catch (e) { app.log.error("stripe handle err", e); Sentry.captureException(e); }
    return { received: true };
  }
});

// ---------- FCM (v1) ----------
import jwtLib from "jsonwebtoken";
async function getGoogleAccessToken() {
  if (!FIREBASE_PROJECT_ID || !FIREBASE_CLIENT_EMAIL || !FIREBASE_PRIVATE_KEY) throw new Error("FCM not configured");
  const nowSec = Math.floor(Date.now() / 1000);
  const header = { alg: "RS256", typ: "JWT" };
  const claim = {
    iss: FIREBASE_CLIENT_EMAIL, sub: FIREBASE_CLIENT_EMAIL,
    aud: "https://oauth2.googleapis.com/token", iat: nowSec, exp: nowSec + 3600,
    scope: "https://www.googleapis.com/auth/firebase.messaging",
  };
  const assertion = jwtLib.sign(claim, FIREBASE_PRIVATE_KEY, { algorithm: "RS256", header });
  const res = await fetchWithRetry("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion }),
  });
  const data = await res.json();
  if (!data.access_token) throw new Error("no access token");
  return data.access_token;
}
async function fcmSendV1(tokens = [], { title = "SoulLift", body = "Hi", data = {} } = {}) {
  if (!tokens || !tokens.length) return 0;
  const access = await getGoogleAccessToken();
  const url = `https://fcm.googleapis.com/v1/projects/${FIREBASE_PROJECT_ID}/messages:send`;
  let sent = 0;
  for (const t of tokens) {
    const payload = { message: { token: t, notification: { title, body }, data: Object.fromEntries(Object.entries(data).map(([k, v]) => [String(k), String(v)])) } };
  const r = await fetchWithRetry(url, { method: "POST", headers: { Authorization: `Bearer ${access}`, "Content-Type": "application/json" }, body: JSON.stringify(payload) });
    if (r.ok) sent++;
    else {
      const txt = await r.text().catch(() => "");
      app.log.warn("fcm send failed", r.status, txt);
    }
    await sleep(50);
  }
  return sent;
}
app.post("/api/notify/register", {
  preHandler: [authMiddleware],
  schema: {
    tags: ['Notify'],
    summary: 'Înregistrează token push pentru utilizator',
    body: { type: 'object', properties: { token: { type: 'string', minLength: 10 } }, required: ['token'] },
    response: { 200: { type: 'object', properties: { ok: { type: 'boolean' } } }, 400: { type: 'object', properties: { error: { type: 'string' } } } }
  }
}, async (req, rep) => {
  const { token } = req.body || {};
  if (!token) return rep.code(400).send({ error: "token required" });
  await query(`insert into push_tokens(email,token) values($1,$2) on conflict(token) do update set email=EXCLUDED.email`, [req.user.email, token]);
  await pushAudit("notify:register", req.user.email, null);
  return { ok: true };
});
app.post("/api/notify/test", {
  preHandler: [authMiddleware],
  schema: {
    tags: ['Notify'],
    summary: 'Trimite push test către token-urile utilizatorului',
    response: { 200: { type: 'object', properties: { ok: { type: 'boolean' }, sent: { type: 'integer', minimum: 0 } } }, 400: { type: 'object', properties: { error: { type: 'string' } } } }
  }
}, async (req, rep) => {
  if (!FIREBASE_PROJECT_ID || !FIREBASE_CLIENT_EMAIL || !FIREBASE_PRIVATE_KEY) {
    return rep.code(400).send({ error: "FCM not configured" });
  }
  const prefs = await getNotificationPrefs(req.user.email);
  if (prefs.mute || isQuietNow(prefs)) {
    await pushAudit("notify:test:muted", req.user.email, { mute: prefs.mute, quiet: isQuietNow(prefs) });
    return { ok: true, sent: 0 };
  }
  const { rows } = await query(`select token from push_tokens where email=$1`, [req.user.email]);
  const tokens = rows.map(r => r.token);
  if (!tokens.length) return rep.code(400).send({ error: "No tokens" });
  const sent = await fcmSendV1(tokens, { title: "SoulLift", body: "Test notification ✅", data: { type: "test" } });
  await pushAudit("notify:test", req.user.email, { sent });
  return { ok: true, sent };
});
app.post("/api/notify/broadcast", {
  preHandler: [authMiddleware],
  config: { rateLimit: { max: 3, timeWindow: '1m' } },
  schema: {
    tags: ['Notify'],
    summary: 'Broadcast push notification',
    body: {
      type: 'object',
      properties: {
        title: { type: 'string', minLength: 1 },
        body: { type: 'string', minLength: 1 },
        proOnly: { type: 'boolean' },
        topic: { type: 'string' }
      },
      required: ['title','body']
    },
    response: { 200: { type: 'object', properties: { ok: { type: 'boolean' }, sent: { type: 'integer', minimum: 0 } } } }
  }
}, async (req, rep) => {
  const { title = "SoulLift", body = "Hello!", proOnly = true, topic = null } = req.body || {};
  const { rows } = await query(`select email, token from push_tokens`);
  const groups = {};
  for (const r of rows) { groups[r.email] = groups[r.email] || []; groups[r.email].push(r.token); }
  let total = 0;
  for (const email of Object.keys(groups)) {
    if (proOnly) {
      const { rows: urows } = await query(`select subscription_status from users where email=$1`, [email]);
      if (urows[0]?.subscription_status !== "active") continue;
    }
    const prefs = await getNotificationPrefs(email);
    // Adaugăm în inbox indiferent de preferințe (util pentru vizualizare în app)
    try { await query(`insert into notifications_inbox(email,title,body,data) values($1,$2,$3,$4)`, [email, title, body, JSON.stringify({ type: "broadcast", topic: topic || undefined })]); } catch {}
    if (prefs.mute || isQuietNow(prefs)) continue;
    if (topic && Array.isArray(prefs.topics) && prefs.topics.length && !prefs.topics.includes(topic)) continue;
    try { total += await fcmSendV1(groups[email], { title, body, data: { type: "broadcast", topic: topic || undefined } }); await sleep(100); }
    catch (e) { app.log.warn("broadcast err", e); }
  }
  await pushAudit("notify:broadcast", null, { total });
  return { ok: true, sent: total };
});

// Preferințe notificări - CRUD
app.get("/api/notify/preferences", {
  preHandler: [authMiddleware],
  schema: {
    tags: ['Notify'],
    summary: 'Obține preferințele de notificare',
    response: { 200: { type: 'object', properties: { ok: { type: 'boolean' }, preferences: { type: 'object' } } } }
  }
}, async (req) => {
  const prefs = await getNotificationPrefs(req.user.email);
  return { ok: true, preferences: prefs };
});
app.post("/api/notify/preferences", {
  preHandler: [authMiddleware],
  schema: {
    tags: ['Notify'],
    summary: 'Setează preferințele de notificare',
    body: { type: 'object', properties: { topics: { type: 'array', items: { type: 'string' } }, mute: { type: 'boolean' }, quiet_hours: { type: 'object', properties: { start: { type: 'string' }, end: { type: 'string' }, timezone: { type: 'string' } } } } },
    response: { 200: { type: 'object', properties: { ok: { type: 'boolean' } } } }
  }
}, async (req) => {
  const { topics = [], mute = false, quiet_hours = null } = req.body || {};
  await query(`insert into notification_preferences(email, topics, mute, quiet_hours)
               values($1,$2,$3,$4)
               on conflict(email) do update set topics=EXCLUDED.topics, mute=EXCLUDED.mute, quiet_hours=EXCLUDED.quiet_hours, updated_at=now()`,
               [req.user.email, JSON.stringify(topics), mute, quiet_hours ? JSON.stringify(quiet_hours) : null]);
  await pushAudit("notify:prefs:update", req.user.email, null);
  return { ok: true };
});

// Inbox notificări
app.get("/api/notify/inbox", {
  preHandler: [authMiddleware],
  schema: {
    tags: ['Notify'],
    summary: 'Inbox notificări pentru utilizator',
    querystring: { type: 'object', properties: { limit: { type: 'integer', minimum: 1, default: 20 }, offset: { type: 'integer', minimum: 0, default: 0 } } },
    response: { 200: { type: 'object', properties: { ok: { type: 'boolean' }, items: { type: 'array' }, total: { type: 'integer' } } } }
  }
}, async (req) => {
  const { limit = 20, offset = 0 } = req.query || {};
  const { rows } = await query(`select id,title,body,data,read,created_at from notifications_inbox where email=$1 order by created_at desc limit $2 offset $3`, [req.user.email, limit, offset]);
  const { rows: c } = await query(`select count(*)::int as cnt from notifications_inbox where email=$1`, [req.user.email]);
  return { ok: true, items: rows, total: c[0]?.cnt || 0 };
});
app.post("/api/notify/inbox/read", {
  preHandler: [authMiddleware],
  schema: {
    tags: ['Notify'],
    summary: 'Marchează notificările ca citite',
    body: { type: 'object', properties: { id: { type: 'integer' }, all: { type: 'boolean' } } },
    response: { 200: { type: 'object', properties: { ok: { type: 'boolean' }, updated: { type: 'integer' } } } }
  }
}, async (req) => {
  const { id = null, all = false } = req.body || {};
  let res;
  if (all) {
    res = await query(`update notifications_inbox set read=true where email=$1 and read=false`, [req.user.email]);
  } else if (id) {
    res = await query(`update notifications_inbox set read=true where email=$1 and id=$2`, [req.user.email, id]);
  } else {
    return { ok: true, updated: 0 };
  }
  await pushAudit("notify:inbox:read", req.user.email, { id, all });
  return { ok: true, updated: res.rowCount || 0 };
});

// ---------- AI-powered features: recommendations, dunning, winback ----------
app.get("/api/recommendations", { preHandler: [authMiddleware] }, async (req) => {
  const email = req.user.email;
  const favs = (await query(`select quote_id from favorites where email=$1`, [email])).rows.map(r => r.quote_id);
  const { rows } = await query(`select id,text,tags,score from ai_quotes order by score desc limit 50`);
  const recs = rows.filter(r => !favs.includes(String(r.id))).slice(0, 10);
  return { ok: true, recommendations: recs };
});

cron.schedule("15 8 * * *", async () => {
  try {
    const { rows } = await query(`select email from users where subscription_status='past_due'`);
    for (const r of rows) {
      if (TELEGRAM_BOT_TOKEN && TELEGRAM_CHAT_ID) {
  await fetchWithRetry(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`, {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ chat_id: TELEGRAM_CHAT_ID, text: `Dunning: ${r.email}` }),
        });
      }
    }
  } catch (e) { app.log.warn("dunning err", e); }
}, { timezone: "Europe/Bucharest" });

cron.schedule("0 9 * * *", async () => {
  try {
    const cutoff = new Date(Date.now() - 14 * 24 * 3600 * 1000).toISOString().slice(0, 10);
    const { rows } = await query(`select email from users where (last_login is null or last_login < $1) and subscription_status!='pro'`, [cutoff]);
    for (const r of rows) {
      if (TELEGRAM_BOT_TOKEN && TELEGRAM_CHAT_ID) {
  await fetchWithRetry(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`, {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ chat_id: TELEGRAM_CHAT_ID, text: `Winback candidate: ${r.email}` }),
        });
      }
    }
  } catch (e) { app.log.warn("winback err", e); }
}, { timezone: "Europe/Bucharest" });

// Daily Stripe reconciliation: ensure DB reflects actual subscription status
cron.schedule("0 2 * * *", async () => {
  if (!pool || !env.STRIPE_SECRET_KEY) return;
  try {
    const { rows } = await query("select email, stripe_customer_id from users where stripe_customer_id is not null");
    for (const u of rows) {
      try {
        const subs = await stripe.subscriptions.list({ customer: u.stripe_customer_id, status: 'all', limit: 1 });
        const sub = subs?.data?.[0];
        if (sub) {
          await query(
            `update users set subscription_tier=$2, subscription_status=$3, stripe_sub_id=$4, current_period_end=$5 where stripe_customer_id=$1`,
            [
              u.stripe_customer_id,
              sub?.items?.data?.[0]?.price?.nickname || null,
              sub.status,
              sub.id,
              (sub.current_period_end || 0) * 1000
            ]
          );
          await pushAudit("stripe:reconcile", u.email, { status: sub.status, subId: sub.id });
        } else {
          await query(
            `update users set subscription_status='canceled', subscription_tier='free', stripe_sub_id=null where stripe_customer_id=$1`,
            [u.stripe_customer_id]
          );
          await pushAudit("stripe:reconcile:none", u.email, {});
        }
      } catch (e) {
        app.log.warn("stripe reconcile user failed", e);
      }
    }
  } catch (e) {
    app.log.error("stripe reconcile error", e);
    Sentry.captureException(e);
  }
}, { timezone: "Europe/Bucharest" });

cron.schedule("30 7 * * *", async () => {
  try {
    const statsRes = await query(`select count(*) filter (where created_at > now() - interval '24 hours') as recent_quotes from ai_quotes`);
    const errors = (await query(`select ts, type, meta from audit_log order by ts desc limit 5`)).rows;
    const lines = [];
    lines.push(`Daily Digest — ${new Date().toLocaleString()}`);
    lines.push(`New AI quotes (24h): ${statsRes.rows[0]?.recent_quotes || 0}`);
    if (errors.length) {
      lines.push("Recent audit:");
      errors.forEach(e => lines.push(` - ${e.type} @ ${e.ts.toISOString()}`));
    }
    const msg = lines.join("\\n");
    if (TELEGRAM_BOT_TOKEN && TELEGRAM_CHAT_ID) {
  await fetchWithRetry(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ chat_id: TELEGRAM_CHAT_ID, text: msg }),
      });
    }
  } catch (e) { app.log.warn("daily digest err", e); }
}, { timezone: "Europe/Bucharest" });

// ---------- admin/test & export ----------
app.post("/admin/telegram/test", {
  config: { rateLimit: { max: 3, timeWindow: '1m' } },
  schema: {
    tags: ['Admin'],
    summary: 'Send test Telegram message',
    body: { type: 'object', properties: { text: { type: 'string', minLength: 1, maxLength: 500 } } },
    response: {
      200: { type: 'object', properties: { ok: { type: 'boolean' } } },
      400: { type: 'object', properties: { error: { type: 'string' } } },
      500: { type: 'object', properties: { error: { type: 'string' } } }
    }
  }
}, async (req, rep) => {
  const { text = "SoulLift test message" } = req.body || {};
  if (!TELEGRAM_BOT_TOKEN || !TELEGRAM_CHAT_ID) return rep.code(400).send({ error: "Telegram not configured" });
  const r = await fetchWithRetry(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ chat_id: TELEGRAM_CHAT_ID, text }),
  });
  if (!r.ok) return rep.code(500).send({ error: "Telegram error" });
  return { ok: true };
});

app.get("/admin/export/json", {
  schema: {
    tags: ['Admin'],
    summary: 'Export data to JSON file',
    response: {
      200: { type: 'object', properties: { ok: { type: 'boolean' }, path: { type: 'string' } } },
      500: { type: 'object', properties: { error: { type: 'string' } } }
    }
  }
}, async (req, rep) => {
  try {
    const users = await query(`select email, created_at, badges, streak, last_login, subscription_status, subscription_tier from users`);
    const favs = await query(`select * from favorites`);
    const aiq = await query(`select id,text,tags,score,created_at from ai_quotes`);
    const payload = { users: users.rows, favorites: favs.rows, ai_quotes: aiq.rows, exported_at: new Date().toISOString() };
    const path = `/tmp/soullift_export_${Date.now()}.json`;
    await fs.promises.writeFile(path, JSON.stringify(payload, null, 2), "utf-8");
    return { ok: true, path };
  } catch (e) { app.log.error("export err", e); return rep.code(500).send({ error: "export failed" }); }
});

app.get("/api/stats", {
  schema: {
    tags: ['System'],
    summary: 'System statistics',
    response: {
      200: {
        type: 'object',
        properties: {
          ok: { type: 'boolean' },
          stats: {
            type: 'object',
            properties: {
              users: { type: 'integer', minimum: 0 },
              ai_quotes: { type: 'integer', minimum: 0 },
              favorites: { type: 'integer', minimum: 0 }
            }
          }
        }
      }
    }
  }
}, async () => {
  const q1 = await query(`select count(*) as users from users`);
  const q2 = await query(`select count(*) as ai_quotes from ai_quotes`);
  const q3 = await query(`select count(*) as favorites from favorites`);
  return { ok: true, stats: { users: Number(q1.rows[0].users || 0), ai_quotes: Number(q2.rows[0].ai_quotes || 0), favorites: Number(q3.rows[0].favorites || 0) } };
});

// ---------- GDPR endpoints ----------
app.get("/api/gdpr/export", {
  preHandler: [authMiddleware],
  schema: {
    tags: ['GDPR'],
    summary: 'Exportă datele personale (GDPR)',
    querystring: { type: 'object', properties: { download: { type: 'boolean', default: false } } },
    response: {
      200: {
        type: 'object',
        properties: {
          ok: { type: 'boolean' },
          data: { type: 'object' }
        }
      },
      404: { type: 'object', properties: { error: { type: 'string' } } }
    }
  }
}, async (req, rep) => {
  const email = req.user.email;
  try {
    const user = (await query(
      `select email, created_at, badges, streak, last_login, subscription_status, subscription_tier, stripe_customer_id, stripe_sub_id, current_period_end from users where email=$1`,
      [email]
    )).rows[0];
    if (!user) return rep.code(404).send({ error: "Utilizator inexistent" });

    const favorites = (await query(
      `select quote_id, created_at from favorites where email=$1 order by created_at desc`,
      [email]
    )).rows;
    const pushTokens = (await query(
      `select token, created_at from push_tokens where email=$1 order by created_at desc`,
      [email]
    )).rows;
    const prefs = (await query(
      `select email, topics, mute, quiet_hours, updated_at from notification_preferences where email=$1`,
      [email]
    )).rows[0] || null;
    const inbox = (await query(
      `select id, title, body, data, read, created_at from notifications_inbox where email=$1 order by created_at desc limit 200`,
      [email]
    )).rows;
    const audit = (await query(
      `select id, ts, type, meta from audit_log where email=$1 order by ts desc limit 200`,
      [email]
    )).rows;

    const { download = false } = req.query || {};
    await pushAudit("gdpr:export", email, { items: { favorites: favorites.length, push_tokens: pushTokens.length, inbox: inbox.length, audit: audit.length } });
    if (download) {
      rep.header('Content-Type', 'application/json');
      rep.header('Content-Disposition', `attachment; filename="gdpr-export-${email}.json"`);
    }
    return { ok: true, data: { user, favorites, push_tokens: pushTokens, notification_preferences: prefs, inbox, audit_log: audit } };
  } catch (e) {
    app.log.error(e);
    return rep.code(500).send({ error: "Export error" });
  }
});

app.post("/api/gdpr/delete", {
  preHandler: [authMiddleware],
  schema: {
    tags: ['GDPR'],
    summary: 'Șterge datele personale (GDPR)',
    body: {
      type: 'object',
      properties: { confirm: { type: 'boolean' } },
      required: ['confirm']
    },
    response: {
      200: {
        type: 'object',
        properties: {
          ok: { type: 'boolean' },
          deleted: { type: 'object' }
        }
      },
      404: { type: 'object', properties: { error: { type: 'string' } } }
    }
  }
}, async (req, rep) => {
  const email = req.user.email;
  const { confirm } = req.body || {};
  if (!confirm) return rep.code(400).send({ error: "Confirmă ștergerea" });
  try {
    const exists = (await query(`select 1 from users where email=$1`, [email])).rows[0];
    if (!exists) return rep.code(404).send({ error: "Utilizator inexistent" });

    // v1: anulăm abonamentul Stripe dacă există
    try {
      const subRow = (await query(`select stripe_sub_id from users where email=$1`, [email])).rows[0];
      const stripeSubId = subRow?.stripe_sub_id;
      if (stripeSubId) {
        await stripe.subscriptions.cancel(stripeSubId);
        await pushAudit("gdpr:stripe_cancel", email, { ok: true, sub_id: stripeSubId, v: "v1" });
      } else {
        await pushAudit("gdpr:stripe_cancel", email, { ok: false, reason: "no_subscription", v: "v1" });
      }
    } catch (e) {
      app.log.warn({ err: e }, "Stripe cancel failed (v1)");
      await pushAudit("gdpr:stripe_cancel", email, { ok: false, error: "cancel_failed", v: "v1" });
    }

    // Dacă utilizatorul are un abonament Stripe, îl anulăm înainte de ștergere
    try {
      const subRow = (await query(`select stripe_sub_id from users where email=$1`, [email])).rows[0];
      const stripeSubId = subRow?.stripe_sub_id;
      if (stripeSubId) {
        await stripe.subscriptions.cancel(stripeSubId);
        await pushAudit("gdpr:stripe_cancel", email, { ok: true, sub_id: stripeSubId });
      } else {
        await pushAudit("gdpr:stripe_cancel", email, { ok: false, reason: "no_subscription" });
      }
    } catch (e) {
      app.log.warn({ err: e }, "Stripe cancel failed");
      await pushAudit("gdpr:stripe_cancel", email, { ok: false, error: "cancel_failed" });
    }

    const favCount = (await query(`select count(*)::int as c from favorites where email=$1`, [email])).rows[0]?.c || 0;
    const tokCount = (await query(`select count(*)::int as c from push_tokens where email=$1`, [email])).rows[0]?.c || 0;
    const prefCount = (await query(`select count(*)::int as c from notification_preferences where email=$1`, [email])).rows[0]?.c || 0;
    const inboxCount = (await query(`select count(*)::int as c from notifications_inbox where email=$1`, [email])).rows[0]?.c || 0;
    const auditCount = (await query(`select count(*)::int as c from audit_log where email=$1`, [email])).rows[0]?.c || 0;

    // Delete user — cascades will remove dependent records
    const delUser = await query(`delete from users where email=$1`, [email]);
    // Anonymize audit logs (keep meta, remove email linkage)
    const anonymized = (await query(`update audit_log set email=null where email=$1`, [email])).rowCount || 0;

    await pushAudit("gdpr:delete", null, { email });
    return {
      ok: true,
      deleted: {
        users: delUser.rowCount || 0,
        favorites: favCount,
        push_tokens: tokCount,
        preferences: prefCount,
        inbox: inboxCount,
        audit_anonymized: anonymized,
        audit_linked_before: auditCount
      }
    };
  } catch (e) {
    app.log.error(e);
    return rep.code(500).send({ error: "Delete error" });
  }
});

// v1 aliases
app.get("/v1/gdpr/export", {
  preHandler: [authMiddleware],
  schema: {
    tags: ['GDPR'],
    summary: 'Exportă datele personale (v1)',
    querystring: { type: 'object', properties: { download: { type: 'boolean', default: false } } },
    response: { 200: { type: 'object', properties: { ok: { type: 'boolean' }, data: { type: 'object' } } } }
  }
}, async (req, rep) => {
  // Proxy to the same handler logic by reusing above queries
  const email = req.user.email;
  try {
    const user = (await query(
      `select email, created_at, badges, streak, last_login, subscription_status, subscription_tier, stripe_customer_id, stripe_sub_id, current_period_end from users where email=$1`,
      [email]
    )).rows[0];
    if (!user) return rep.code(404).send({ error: "Utilizator inexistent" });
    const favorites = (await query(`select quote_id, created_at from favorites where email=$1 order by created_at desc`, [email])).rows;
    const pushTokens = (await query(`select token, created_at from push_tokens where email=$1 order by created_at desc`, [email])).rows;
    const prefs = (await query(`select email, topics, mute, quiet_hours, updated_at from notification_preferences where email=$1`, [email])).rows[0] || null;
    const inbox = (await query(`select id, title, body, data, read, created_at from notifications_inbox where email=$1 order by created_at desc limit 200`, [email])).rows;
    const audit = (await query(`select id, ts, type, meta from audit_log where email=$1 order by ts desc limit 200`, [email])).rows;
    const { download = false } = req.query || {};
    await pushAudit("gdpr:export", email, { items: { favorites: favorites.length, push_tokens: pushTokens.length, inbox: inbox.length, audit: audit.length }, v: "v1" });
    if (download) {
      rep.header('Content-Type', 'application/json');
      rep.header('Content-Disposition', `attachment; filename="gdpr-export-${email}.json"`);
    }
    return { ok: true, data: { user, favorites, push_tokens: pushTokens, notification_preferences: prefs, inbox, audit_log: audit } };
  } catch (e) {
    app.log.error(e);
    return rep.code(500).send({ error: "Export error" });
  }
});

app.post("/v1/gdpr/delete", {
  preHandler: [authMiddleware],
  schema: {
    tags: ['GDPR'],
    summary: 'Șterge datele personale (v1)',
    body: { type: 'object', properties: { confirm: { type: 'boolean' } }, required: ['confirm'] },
    response: { 200: { type: 'object', properties: { ok: { type: 'boolean' }, deleted: { type: 'object' } } } }
  }
}, async (req, rep) => {
  const email = req.user.email;
  const { confirm } = req.body || {};
  if (!confirm) return rep.code(400).send({ error: "Confirmă ștergerea" });
  try {
    const exists = (await query(`select 1 from users where email=$1`, [email])).rows[0];
    if (!exists) return rep.code(404).send({ error: "Utilizator inexistent" });
    const favCount = (await query(`select count(*)::int as c from favorites where email=$1`, [email])).rows[0]?.c || 0;
    const tokCount = (await query(`select count(*)::int as c from push_tokens where email=$1`, [email])).rows[0]?.c || 0;
    const prefCount = (await query(`select count(*)::int as c from notification_preferences where email=$1`, [email])).rows[0]?.c || 0;
    const inboxCount = (await query(`select count(*)::int as c from notifications_inbox where email=$1`, [email])).rows[0]?.c || 0;
    const auditCount = (await query(`select count(*)::int as c from audit_log where email=$1`, [email])).rows[0]?.c || 0;
    const delUser = await query(`delete from users where email=$1`, [email]);
    const anonymized = (await query(`update audit_log set email=null where email=$1`, [email])).rowCount || 0;
    await pushAudit("gdpr:delete", null, { email, v: "v1" });
    return { ok: true, deleted: { users: delUser.rowCount || 0, favorites: favCount, push_tokens: tokCount, preferences: prefCount, inbox: inboxCount, audit_anonymized: anonymized, audit_linked_before: auditCount } };
  } catch (e) {
    app.log.error(e);
    return rep.code(500).send({ error: "Delete error" });
  }
});

// ---------- start ----------
try {
  await app.listen({ port: PORT, host: "0.0.0.0" });
  app.log.info(`SoulLift listening on :${PORT}`);
} catch (e) {
  Sentry.captureException(e);
  app.log.error(e);
  process.exit(1);
}
