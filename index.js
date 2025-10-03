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

// ---------- basic setup ----------
const isProd = process.env.NODE_ENV === "production";
const app = Fastify({
  logger: { level: isProd ? "info" : "debug" },
  bodyLimit: 64 * 1024,
});

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "soul-lift-secret";
const FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:5173";

// Flags/keys
const USE_OPENAI = (process.env.USE_OPENAI || "true").toLowerCase() !== "false";
const OPENAI_KEY = process.env.OPENAI_API_KEY || "";
const DEEPL_KEY = process.env.DEEPL_API_KEY || "";
const DEEPL_ENDPOINT = process.env.DEEPL_ENDPOINT || "https://api-free.deepl.com";
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || "";
const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID || "";

// Stripe
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY || "", { apiVersion: "2024-06-20" });
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || "";
const STRIPE_PRICE_ID_MONTHLY = process.env.STRIPE_PRICE_ID_MONTHLY || "";
const STRIPE_PRICE_ID_YEARLY = process.env.STRIPE_PRICE_ID_YEARLY || "";

// FCM v1
const FIREBASE_PROJECT_ID = process.env.FIREBASE_PROJECT_ID || "";
const FIREBASE_CLIENT_EMAIL = process.env.FIREBASE_CLIENT_EMAIL || "";
const FIREBASE_PRIVATE_KEY = (process.env.FIREBASE_PRIVATE_KEY || "").replace(/\\n/g, "\n");

// Sentry
if (process.env.SENTRY_DSN) {
  Sentry.init({ dsn: process.env.SENTRY_DSN, tracesSampleRate: 0.05 });
  app.log.info("Sentry initialized");
}

// Postgres
const { Pool } = pg;

// Pentru testare locală, verificăm dacă avem DATABASE_URL
let pool;
if (process.env.DATABASE_URL) {
  pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.DATABASE_SSL ? { rejectUnauthorized: false } : undefined,
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
const fetchWithRetry = fetch;

// ---------- plugins ----------
await app.register(cors, { origin: true, credentials: true });
await app.register(helmet, { global: true, contentSecurityPolicy: false });
await app.register(rateLimit, {
  max: 200,
  timeWindow: 60_000,
  keyGenerator: (req) => req.headers["x-forwarded-for"] || req.ip,
});

// Înregistrăm sistemul de logging avansat
await app.register(compress);
await app.register(swagger, { openapi: { info: { title: "SoulLift API", version: "10.1.0" } } });
await app.register(swaggerUI, { routePrefix: "/docs" });
await app.register(metrics, { endpoint: "/metrics", defaultMetrics: { enabled: true } });
await app.register(fastifyRawBody, { field: "rawBody", global: false, runFirst: true });

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
};
await ensureTables();

// ---------- audit helper ----------
async function pushAudit(type, email, meta) {
  try {
    await query(`insert into audit_log(type,email,meta) values($1,$2,$3)`,
      [type, email, meta ? JSON.stringify(meta) : null]);
  } catch (e) { app.log.warn("audit error", e); }
}

// ---------- auth helpers ----------
function generateToken(email, exp = "1h") { return jwt.sign({ email }, JWT_SECRET, { expiresIn: exp }); }
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
app.get("/health", async () => ({ ok: true, ts: Date.now() }));
app.get("/healthz", async () => ({ ok: true, ts: Date.now() }));
app.get("/config", async () => ({
  ok: true,
  features: {
    openai: aiEnabled(), deepl: Boolean(DEEPL_KEY),
    fcm: Boolean(FIREBASE_PROJECT_ID && FIREBASE_CLIENT_EMAIL && FIREBASE_PRIVATE_KEY),
    sentry: Boolean(process.env.SENTRY_DSN),
  },
}));

// languages
app.get("/api/languages", async () =>
  ({ ok: true, languages: ["EN", "RO", "FR", "DE", "ES", "IT", "PT", "RU", "JA", "ZH", "NL", "PL", "TR"] }));

// auth
app.post("/api/register", async (req, rep) => {
  const { email, password } = req.body || {};
  if (!email || !password) return rep.code(400).send({ error: "Email and password required." });
  const { rows } = await query(`select * from users where email=$1`, [email]);
  if (rows[0]) return rep.code(409).send({ error: "User exists" });
  const hash = await bcrypt.hash(password, 10);
  await query(`insert into users(email,password_hash,created_at) values($1,$2,now())`, [email, hash]);
  await pushAudit("register", email, null);
  const access = generateToken(email, "1h"), refresh = generateToken(email, "7d");
  return { ok: true, user: { email }, tokens: { access, refresh } };
});

app.post("/api/login", async (req, rep) => {
  const { email, password } = req.body || {};
  if (!email || !password) return rep.code(400).send({ error: "Email and password required." });
  const { rows } = await query(`select * from users where email=$1`, [email]);
  const user = rows[0];
  if (!user || !user.password_hash) return rep.code(401).send({ error: "Invalid credentials." });
  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return rep.code(401).send({ error: "Invalid credentials." });
  await updateStreakOnLogin(email);
  await pushAudit("login", email, null);
  const access = generateToken(email, "1h"), refresh = generateToken(email, "7d");
  return { ok: true, user: { email, badges: user.badges || [] }, tokens: { access, refresh } };
});

app.post("/api/refresh", async (req, rep) => {
  const { token } = req.body || {};
  if (!token) return rep.code(400).send({ error: "Missing token" });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const access = generateToken(payload.email, "1h");
    return { ok: true, accessToken: access };
  } catch { return rep.code(401).send({ error: "Invalid refresh token" }); }
});

// categories & quotes
app.get("/api/categories", async () => ({ ok: true, categories }));
app.get("/api/quote", async (req, rep) => {
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
  return { ok: true, quote: q };
});

// AI export (read-only)
app.get("/api/ai/export", async () => {
  const { rows } = await query(`select id,text,tags,score,created_at from ai_quotes order by created_at desc limit 200`);
  return { ok: true, quotes: rows };
});

// favorites
app.post("/api/favorites/toggle", { preHandler: [authMiddleware] }, async (req, rep) => {
  const { quoteId } = req.body || {};
  if (!quoteId) return rep.code(400).send({ error: "quoteId required" });
  const email = req.user.email;
  const { rows } = await query(`select * from favorites where email=$1 and quote_id=$2`, [email, quoteId]);
  if (rows[0]) await query(`delete from favorites where email=$1 and quote_id=$2`, [email, quoteId]);
  else await query(`insert into favorites(email,quote_id) values($1,$2)`, [email, quoteId]);
  await pushAudit("favorite:toggle", email, { quoteId });
  return { ok: true };
});
app.get("/api/favorites", { preHandler: [authMiddleware] }, async (req) => {
  const email = req.user.email;
  const { rows } = await query(`select quote_id from favorites where email=$1`, [email]);
  return { ok: true, items: rows.map(r => QUOTES.find(q => q.id === r.quote_id)).filter(Boolean) };
});

// search quotes (static + AI)
app.get("/api/search", async (req, rep) => {
  const { q, limit = 20, offset = 0 } = req.query || {};
  if (!q || q.trim().length < 2) {
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

  const searchTerm = q.trim().toLowerCase();
  const results = [];

  try {
    // 1. Search static quotes
    const staticMatches = QUOTES.filter(quote => {
      // Skip premium quotes for non-pro users
      if (quote.premium && !isPro) return false;
      
      const textMatch = quote.text.toLowerCase().includes(searchTerm);
      const authorMatch = quote.author.toLowerCase().includes(searchTerm);
      const sourceMatch = quote.source?.toLowerCase().includes(searchTerm);
      
      return textMatch || authorMatch || sourceMatch;
    }).map(quote => ({
      ...quote,
      source_type: 'static',
      relevance_score: calculateRelevanceScore(quote, searchTerm)
    }));

    results.push(...staticMatches);

    // 2. Search AI quotes (PostgreSQL full-text search)
    if (pool) {
      const aiSearchQuery = `
        SELECT id, text, tags, score, created_at,
               ts_rank(to_tsvector('english', text), plainto_tsquery('english', $1)) as rank
        FROM ai_quotes 
        WHERE to_tsvector('english', text) @@ plainto_tsquery('english', $1)
           OR text ILIKE $2
           OR EXISTS (
             SELECT 1 FROM jsonb_array_elements_text(tags) as tag 
             WHERE tag ILIKE $2
           )
        ORDER BY rank DESC, score DESC
        LIMIT $3 OFFSET $4
      `;
      
      const { rows: aiQuotes } = await query(aiSearchQuery, [
        searchTerm, 
        `%${searchTerm}%`, 
        parseInt(limit), 
        parseInt(offset)
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
        relevance_score: quote.rank || 0,
        created_at: quote.created_at
      }));

      results.push(...aiMatches);
    }

    // 3. Sort by relevance and apply pagination
    const sortedResults = results
      .sort((a, b) => b.relevance_score - a.relevance_score)
      .slice(parseInt(offset), parseInt(offset) + parseInt(limit));

    // 4. Log search audit
    await pushAudit("search:query", email, { 
      query: searchTerm, 
      resultsCount: sortedResults.length,
      isPro 
    });

    return { 
      ok: true, 
      results: sortedResults,
      total: results.length,
      query: searchTerm,
      pagination: {
        limit: parseInt(limit),
        offset: parseInt(offset),
        hasMore: results.length > parseInt(offset) + parseInt(limit)
      }
    };

  } catch (error) {
    app.log.error("Search error:", error);
    return rep.code(500).send({ error: "Search failed" });
  }
});

// Helper function for relevance scoring
function calculateRelevanceScore(quote, searchTerm) {
  let score = 0;
  const text = quote.text.toLowerCase();
  const author = quote.author.toLowerCase();
  const source = quote.source?.toLowerCase() || "";
  
  // Exact phrase match gets highest score
  if (text.includes(searchTerm)) score += 10;
  if (author.includes(searchTerm)) score += 8;
  if (source.includes(searchTerm)) score += 5;
  
  // Word matches
  const searchWords = searchTerm.split(' ');
  searchWords.forEach(word => {
    if (word.length > 2) {
      if (text.includes(word)) score += 3;
      if (author.includes(word)) score += 2;
      if (source.includes(word)) score += 1;
    }
  });
  
  return score;
}

// translate
app.post("/api/translate", async (req, rep) => {
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
app.post("/api/billing/checkout", { preHandler: [authMiddleware] }, async (req, rep) => {
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

app.get("/api/billing/portal", { preHandler: [authMiddleware] }, async (req) => {
  const { rows } = await query(`select stripe_customer_id from users where email=$1`, [req.user.email]);
  const customerId = rows[0]?.stripe_customer_id;
  if (!customerId) return { ok: false, error: "No Stripe customer" };
  const portal = await stripe.billingPortal.sessions.create({ customer: customerId, return_url: `${FRONTEND_URL}/account` });
  return { ok: true, url: portal.url };
});

app.route({
  method: "POST",
  url: "/api/stripe/webhook",
  config: { rawBody: true },
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
  const res = await fetch("https://oauth2.googleapis.com/token", {
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
    const r = await fetch(url, { method: "POST", headers: { Authorization: `Bearer ${access}`, "Content-Type": "application/json" }, body: JSON.stringify(payload) });
    if (r.ok) sent++;
    else {
      const txt = await r.text().catch(() => "");
      app.log.warn("fcm send failed", r.status, txt);
    }
    await sleep(50);
  }
  return sent;
}
app.post("/api/notify/register", { preHandler: [authMiddleware] }, async (req, rep) => {
  const { token } = req.body || {};
  if (!token) return rep.code(400).send({ error: "token required" });
  await query(`insert into push_tokens(email,token) values($1,$2) on conflict(token) do update set email=EXCLUDED.email`, [req.user.email, token]);
  await pushAudit("notify:register", req.user.email, null);
  return { ok: true };
});
app.post("/api/notify/test", { preHandler: [authMiddleware] }, async (req, rep) => {
  const { rows } = await query(`select token from push_tokens where email=$1`, [req.user.email]);
  const tokens = rows.map(r => r.token);
  if (!tokens.length) return rep.code(400).send({ error: "No tokens" });
  const sent = await fcmSendV1(tokens, { title: "SoulLift", body: "Test notification ✅", data: { type: "test" } });
  await pushAudit("notify:test", req.user.email, { sent });
  return { ok: true, sent };
});
app.post("/api/notify/broadcast", async (req, rep) => {
  const { title = "SoulLift", body = "Hello!", proOnly = true } = req.body || {};
  const { rows } = await query(`select email, token from push_tokens`);
  const groups = {};
  for (const r of rows) { groups[r.email] = groups[r.email] || []; groups[r.email].push(r.token); }
  let total = 0;
  for (const email of Object.keys(groups)) {
    if (proOnly) {
      const { rows: urows } = await query(`select subscription_status from users where email=$1`, [email]);
      if (urows[0]?.subscription_status !== "active") continue;
    }
    try { total += await fcmSendV1(groups[email], { title, body, data: { type: "broadcast" } }); await sleep(100); }
    catch (e) { app.log.warn("broadcast err", e); }
  }
  await pushAudit("notify:broadcast", null, { total });
  return { ok: true, sent: total };
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
        await fetch(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`, {
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
        await fetch(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`, {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ chat_id: TELEGRAM_CHAT_ID, text: `Winback candidate: ${r.email}` }),
        });
      }
    }
  } catch (e) { app.log.warn("winback err", e); }
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
      await fetch(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ chat_id: TELEGRAM_CHAT_ID, text: msg }),
      });
    }
  } catch (e) { app.log.warn("daily digest err", e); }
}, { timezone: "Europe/Bucharest" });

// ---------- admin/test & export ----------
app.post("/admin/telegram/test", async (req, rep) => {
  const { text = "SoulLift test message" } = req.body || {};
  if (!TELEGRAM_BOT_TOKEN || !TELEGRAM_CHAT_ID) return rep.code(400).send({ error: "Telegram not configured" });
  const r = await fetch(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ chat_id: TELEGRAM_CHAT_ID, text }),
  });
  if (!r.ok) return rep.code(500).send({ error: "Telegram error" });
  return { ok: true };
});

app.get("/admin/export/json", async (req, rep) => {
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

app.get("/api/stats", async () => {
  const q1 = await query(`select count(*) as users from users`);
  const q2 = await query(`select count(*) as ai_quotes from ai_quotes`);
  const q3 = await query(`select count(*) as favorites from favorites`);
  return { ok: true, stats: { users: q1.rows[0].users, ai_quotes: q2.rows[0].ai_quotes, favorites: q3.rows[0].favorites } };
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
