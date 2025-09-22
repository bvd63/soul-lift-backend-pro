// index.js — SoulLift (all-in-one, Stripe subs real + premium gating + auth + AI quotes + translations + automation)
// ✅ versiunea aceasta păstrează TOT ce aveai și adaugă: health alias /health,
// JWT refresh rotation + blacklist, rate-limit granular pe login,
// retry/backoff + circuit breaker, queue in-memory, notificări FCM (token registry + send),
// observabilitate (onError hook, optional Sentry), daily digest AI (Telegram),
// /config read-only, moderare AI, dedup AI quotes, basic audit log.

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
import fs from "fs";
import fetch from "node-fetch";
import cron from "node-cron";
import Stripe from "stripe";
import fastifyRawBody from "fastify-raw-body"; // ✅ raw body corect pentru Stripe

import cache from "./src/utils/memoryCache.js";

// ----------------- core setup
const isProd = process.env.NODE_ENV === "production";
const app = Fastify({
  logger: { level: isProd ? "info" : "debug" },
  bodyLimit: 32 * 1024
});

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "soul-lift-secret";

const FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:5173";
const APP_BASE_URL = process.env.APP_BASE_URL || `http://localhost:${PORT}`;

// OpenAI / DeepL
const OPENAI_KEY = process.env.OPENAI_API_KEY || "";
const DEEPL_KEY = process.env.DEEPL_API_KEY || "";
const DEEPL_ENDPOINT = "https://api-free.deepl.com";

// Stripe
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY || "", { apiVersion: "2024-06-20" });
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || "";
const STRIPE_PRICE_ID_MONTHLY = process.env.STRIPE_PRICE_ID_MONTHLY || "";
const STRIPE_PRICE_ID_YEARLY = process.env.STRIPE_PRICE_ID_YEARLY || "";

// 🔹 NEW: Observability externă (opțional)
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || "";        // pentru digest zilnic erori/status
const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID || "";

// 🔹 NEW: Notificări push (FCM)
const FCM_SERVER_KEY = process.env.FCM_SERVER_KEY || "";                // server key (legacy) – simplu de test
// Pentru producție recomand FCM HTTP v1 cu OAuth; aici e varianta „practică” cu server key dacă există.

// 🔹 NEW: Circuit Breaker & Retry
const RETRY_MAX = 3;
const RETRY_BASE_DELAY = 500; // ms
let CIRCUIT_OPEN_UNTIL = 0;   // timestamp ms

async function sleep(ms){ return new Promise(r=>setTimeout(r, ms)); }
function isCircuitOpen(){ return Date.now() < CIRCUIT_OPEN_UNTIL; }
function tripCircuit(ms=10_000){ CIRCUIT_OPEN_UNTIL = Date.now()+ms; app.log.warn(`⚡ Circuit open for ${ms}ms`); }

async function fetchWithRetry(url, options={}, {max=RETRY_MAX, baseDelay=RETRY_BASE_DELAY, label="fetch"} = {}) {
  if (isCircuitOpen()) throw new Error(`CircuitOpen: skipping ${label}`);
  let lastErr;
  for (let i=0;i<max;i++){
    try {
      const res = await fetch(url, options);
      if (!res.ok) throw new Error(`${label} HTTP ${res.status}`);
      return res;
    } catch (err) {
      lastErr = err;
      const delay = baseDelay * Math.pow(2,i);
      app.log.warn({ err: String(err) }, `Retry ${i+1}/${max} for ${label} in ${delay}ms`);
      await sleep(delay);
    }
  }
  // prea multe eșecuri → deschidem circuitul scurt
  tripCircuit(15_000);
  throw lastErr;
}

// ----------------- plugins
await app.register(cors, { origin: true, credentials: true });
await app.register(helmet, { global: true, contentSecurityPolicy: false });
await app.register(rateLimit, {
  max: 120,
  timeWindow: 60_000,
  hook: "onSend",
  keyGenerator: (req) => req.headers["x-forwarded-for"] || req.ip
});
await app.register(compress);
await app.register(swagger, {
  openapi: { info: { title: "SoulLift API", version: "7.2.0" } } // 🔹 bumped
});
await app.register(swaggerUI, { routePrefix: "/docs" });
await app.register(metrics, { endpoint: "/metrics", defaultMetrics: { enabled: true } });

// ✅ raw body pentru Stripe (doar unde cerem config.rawBody)
await app.register(fastifyRawBody, {
  field: "rawBody",
  global: false,
  runFirst: true
});

// 🔹 NEW: Sentry (opțional, fără dep hard). Dacă ai @sentry/node în deps și SENTRY_DSN setat, se activează.
let Sentry = null;
if (process.env.SENTRY_DSN) {
  try {
    const mod = await import("@sentry/node");
    Sentry = mod.default || mod;
    Sentry.init({ dsn: process.env.SENTRY_DSN, tracesSampleRate: 0.05 });
    app.log.info("Sentry initialized.");
  } catch {
    app.log.warn("Sentry not available. Skipping.");
  }
}

// ----------------- in-memory stores
const users = new Map(); // key = email, value = user object
let stats = {
  quotes: 0,
  translations: 0,
  logins: 0,
  registers: 0,
  favorites: 0,
  playlistCreates: 0,
  shareViews: 0,
  aiQuotesGenerated: 0,
  checkouts: 0,
  webhookEvents: 0
};

// 🔹 NEW: audit log minimal + error buffer pentru digest
const audit = [];
const errorsBuffer = []; // ultimele ~200 erori
const MAX_AUDIT = 500;
const MAX_ERRORS = 200;
function pushAudit(evt){ audit.push({ ts: Date.now(), ...evt }); if (audit.length>MAX_AUDIT) audit.shift(); }
function pushErr(err){ errorsBuffer.push({ ts: Date.now(), err: String(err) }); if (errorsBuffer.length>MAX_ERRORS) errorsBuffer.shift(); }

// 🔹 NEW: refresh blacklist (JWT rotation)
const refreshBlacklist = new Set();

// 🔹 NEW: notificări – registry de tokenuri FCM per user
const pushTokens = new Map(); // email -> Set(tokens)

// ----------------- catalog / content
const categories = JSON.parse(fs.readFileSync("./categories.json", "utf-8"));
const QUOTES = [
  { id: "q1", text: "Your future is created by what you do today, not tomorrow.", author: "Robert Kiyosaki", source: "Interview", year: 2001, premium: false },
  { id: "q2", text: "Success is not for the lazy.", author: "Jim Rohn", source: "Seminar", year: 1985, premium: false },
  { id: "q3", text: "Focus on progress, not perfection.", author: "Bill Gates", source: "Talk", year: 2010, premium: false },
  { id: "q4", text: "Gratitude turns what we have into enough.", author: "Aesop", source: "Fables", year: -550, premium: true }
];
const PREMIUM_COLLECTIONS = [
  { id: "stoicism", name: "Stoicism Starter", items: ["q4"] },
  { id: "deep-focus", name: "Deep Focus", items: ["q2", "q3"] }
];
const SUPPORTED_LANGS = ["EN","RO","FR","DE","ES","IT","PT","RU","JA","ZH","NL","PL","TR"];

// ----------------- AI moderation / quality (basic)  🔹 NEW
async function isContentAllowed(text){
  if (!OPENAI_KEY) return true; // dacă nu avem cheie, nu blocăm
  try {
    // model „omni-moderation-latest” (înlocuibil dacă nu e disponibil)
    const res = await fetchWithRetry("https://api.openai.com/v1/moderations", {
      method: "POST",
      headers: { Authorization: `Bearer ${OPENAI_KEY}`, "Content-Type": "application/json" },
      body: JSON.stringify({ model: "omni-moderation-latest", input: text })
    }, { label: "moderation" });
    const data = await res.json();
    const flagged = data?.results?.[0]?.flagged;
    return !flagged;
  } catch (e) {
    pushErr(e);
    return true; // în caz de eroare, nu blocăm
  }
}

// ----------------- AI Quotes setup
let AI_QUOTES = [];
const aiQuoteSet = new Set(); // 🔹 NEW dedup (normalize)

// helper normalizare
function norm(s){ return (s||"").toLowerCase().replace(/\s+/g," ").trim(); }

async function generateAIQuote() {
  if (!OPENAI_KEY) return null;
  const body = {
    model: "gpt-4o-mini",
    messages: [
      { role: "system", content: "Generate a short motivational quote under 120 characters. Return ONLY the quote." },
      { role: "user", content: "Give me one motivational quote." }
    ],
    temperature: 0.8,
    max_tokens: 60
  };
  try {
    const res = await fetchWithRetry("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: { Authorization: `Bearer ${OPENAI_KEY}`, "Content-Type": "application/json" },
      body: JSON.stringify(body)
    }, { label: "openai:ai-quote" });
    const data = await res.json();
    const q = data?.choices?.[0]?.message?.content?.trim() || null;
    if (!q) return null;
    // moderare
    const allowed = await isContentAllowed(q);
    if (!allowed) return null;
    return q;
  } catch (e) {
    pushErr(e);
    return null;
  }
}

// 🔹 NEW: queue simplă in-memory cu backoff pentru taskuri non-critice
const taskQueue = [];
let queueRunning = false;
async function runQueue(){
  if (queueRunning) return;
  queueRunning = true;
  while (taskQueue.length){
    const task = taskQueue.shift();
    try { await task(); }
    catch(e){ pushErr(e); }
    await sleep(250); // mic backoff între taskuri
  }
  queueRunning = false;
}
function enqueue(fn){ taskQueue.push(fn); runQueue(); }

async function generateBatch(count = 10) {
  const list = [];
  for (let i = 0; i < count; i++) {
    try {
      const q = await generateAIQuote();
      if (q) {
        const key = norm(q);
        if (!aiQuoteSet.has(key)) {
          aiQuoteSet.add(key);
          list.push({ text: q, createdAt: Date.now() });
        }
      }
    } catch(e){ pushErr(e); }
    await sleep(1200);
  }
  AI_QUOTES = list;
  stats.aiQuotesGenerated += list.length;
  return list;
}

// rulează la pornire
await generateBatch(10);

// rulează zilnic la ora 06:00
cron.schedule("0 6 * * *", async () => {
  app.log.info("⏰ Cron: generating AI quotes...");
  enqueue(async ()=>{ await generateBatch(10); });
});

// 🔹 NEW: daily digest (erori + status) la 07:30
cron.schedule("30 7 * * *", async () => {
  try {
    const lines = [];
    lines.push(`🗓 ${new Date().toLocaleString()} — Daily Digest SoulLift`);
    lines.push(`• Uptime approx (process): ok`);
    lines.push(`• Stats: quotes=${stats.quotes}, aiGen=${stats.aiQuotesGenerated}, logins=${stats.logins}, registers=${stats.registers}, webhooks=${stats.webhookEvents}`);
    if (errorsBuffer.length) {
      lines.push(`• Last errors (${Math.min(5, errorsBuffer.length)}):`);
      const last5 = errorsBuffer.slice(-5);
      last5.forEach(e => lines.push(`   - ${new Date(e.ts).toISOString()}: ${e.err}`));
    } else {
      lines.push(`• No errors in the last 24h 🎉`);
    }
    const msg = lines.join("\n");
    if (TELEGRAM_BOT_TOKEN && TELEGRAM_CHAT_ID) {
      await fetchWithRetry(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ chat_id: TELEGRAM_CHAT_ID, text: msg })
      }, { label: "telegram:digest" });
    }
  } catch (e) { pushErr(e); }
});

// ----------------- helpers (auth, jwt, streaks, users)
function generateToken(email, exp = "1h") {
  return jwt.sign({ email }, JWT_SECRET, { expiresIn: exp });
}

function authMiddleware(req, rep, done) {
  const auth = req.headers.authorization;
  if (!auth) return rep.code(401).send({ error: "Missing Authorization header" });
  const token = auth.split(" ")[1];
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    done();
  } catch {
    return rep.code(401).send({ error: "Invalid token" });
  }
}

function todayStr() { return new Date().toISOString().slice(0, 10); }

function updateStreakOnLogin(user) {
  const last = user.lastLogin || null;
  const today = todayStr();
  if (last === today) return;
  if (!last) user.streak = 1;
  else {
    const dLast = new Date(last);
    const dPrev = new Date(dLast.getTime() + 24*3600*1000);
    const isYesterday = dPrev.toISOString().slice(0, 10) === today;
    user.streak = isYesterday ? (user.streak||0)+1 : 1;
  }
  user.lastLogin = today;
  user.badges = user.badges || [];
  if (user.streak === 3 && !user.badges.includes("Streak 3")) user.badges.push("Streak 3");
  if (user.streak === 7 && !user.badges.includes("Streak 7")) user.badges.push("Streak 7");
  if (user.streak === 14 && !user.badges.includes("Streak 14")) user.badges.push("Streak 14");
}

function getOrCreateUserByEmail(email) {
  if (!users.has(email)) {
    users.set(email, {
      email,
      passwordHash: null,
      createdAt: Date.now(),
      favorites: [],
      badges: [],
      streak: 0,
      lastLogin: null,
      // subscripție
      subscription: {
        status: "inactive", // inactive | active | past_due | canceled
        tier: "free",       // free | pro
        currentPeriodEnd: null,
        stripeCustomerId: null,
        stripeSubId: null
      }
    });
  }
  return users.get(email);
}

function requirePro(req, rep, done) {
  if (!req.user?.email) return rep.code(401).send({ error: "Unauthorized" });
  const user = users.get(req.user.email);
  if (!user) return rep.code(401).send({ error: "Unauthorized" });
  const ok = user.subscription?.status === "active" && user.subscription?.tier === "pro";
  if (!ok) return rep.code(402).send({ error: "Payment Required", hint: "Upgrade to Pro to access this content." });
  done();
}

// ----------------- traduceri
async function translateWithOpenAI(text, targetLang) {
  if (!OPENAI_KEY) return null;
  const body = {
    model: "gpt-4o-mini",
    messages: [
      { role: "system", content: "Return ONLY the translated text." },
      { role: "user", content: `Translate to ${targetLang}:\n${text}` }
    ],
    temperature: 0.2
  };
  try {
    const res = await fetchWithRetry("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: { Authorization: `Bearer ${OPENAI_KEY}`, "Content-Type": "application/json" },
      body: JSON.stringify(body)
    }, { label: "openai:translate" });
    const data = await res.json();
    return data?.choices?.[0]?.message?.content?.trim() || null;
  } catch (e){ pushErr(e); return null; }
}
async function translateWithDeepL(text, targetLang) {
  if (!DEEPL_KEY) return null;
  try {
    const params = new URLSearchParams({ auth_key: DEEPL_KEY, text, target_lang: String(targetLang||"EN").toUpperCase() });
    const res = await fetchWithRetry(`${DEEPL_ENDPOINT}/v2/translate`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: params
    }, { label: "deepl:translate" });
    const data = await res.json();
    return data?.translations?.[0]?.text || null;
  } catch (e){ pushErr(e); return null; }
}
async function translateText(text, targetLang="EN") {
  if (!text) return "";
  let translated = null;
  try { translated = await translateWithOpenAI(text, targetLang); } catch(e){ pushErr(e); }
  if (!translated) { try { translated = await translateWithDeepL(text, targetLang); } catch(e){ pushErr(e); } }
  if (translated && translated!==text) stats.translations++;
  return translated || text;
}

// ----------------- routes: health & misc
app.get("/healthz", async () => ({ ok: true, ts: Date.now() }));
app.get("/health", async () => ({ ok: true, ts: Date.now() })); // 🔹 NEW alias pentru Render Health Check
app.get("/api/languages", async () => ({ ok: true, languages: SUPPORTED_LANGS }));

// 🔹 NEW: /config read-only (rapid debug, fără secrete)
app.get("/config", async () => ({
  ok: true,
  env: {
    node: process.version,
    isProd,
    features: {
      stripe: Boolean(process.env.STRIPE_SECRET_KEY),
      openai: Boolean(OPENAI_KEY),
      deepl: Boolean(DEEPL_KEY),
      telegramDigest: Boolean(TELEGRAM_BOT_TOKEN && TELEGRAM_CHAT_ID),
      fcm: Boolean(FCM_SERVER_KEY),
      sentry: Boolean(process.env.SENTRY_DSN),
      circuitOpen: isCircuitOpen()
    }
  }
}));

// ----------------- routes: auth (simple)
app.post("/api/register", async (req, rep) => {
  const { email, password } = req.body || {};
  if (!email || !password) return rep.code(400).send({ error: "Email and password required." });
  if (users.has(email)) return rep.code(409).send({ error: "User already exists." });
  const passwordHash = await bcrypt.hash(password, 10);
  const user = getOrCreateUserByEmail(email);
  user.passwordHash = passwordHash;
  stats.registers++;
  pushAudit({ type: "register", email });
  const accessToken = generateToken(email, "1h");
  const refreshToken = generateToken(email, "7d");
  return { ok: true, user: safeUser(user), tokens: { accessToken, refreshToken } };
});

// 🔹 NEW: rate-limit granular pe login
app.post("/api/login", {
  config: { rateLimit: { max: 5, timeWindow: "1 minute" } }
}, async (req, rep) => {
  const { email, password } = req.body || {};
  if (!email || !password) return rep.code(400).send({ error: "Email and password required." });
  const user = users.get(email);
  if (!user?.passwordHash) return rep.code(401).send({ error: "Invalid credentials." });
  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return rep.code(401).send({ error: "Invalid credentials." });
  updateStreakOnLogin(user);
  stats.logins++;
  pushAudit({ type: "login", email });
  const accessToken = generateToken(email, "1h");
  const refreshToken = generateToken(email, "7d");
  return { ok: true, user: safeUser(user), tokens: { accessToken, refreshToken } };
});

// 🔹 NEW: refresh rotation + blacklist
app.post("/api/refresh", async (req, rep) => {
  const { token } = req.body || {};
  if (!token) return rep.code(400).send({ error: "Missing token." });
  if (refreshBlacklist.has(token)) return rep.code(401).send({ error: "Token rotated. Please use the latest refresh token." });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    // rotim: invalidăm tokenul vechi, emitem pereche nouă
    refreshBlacklist.add(token);
    const accessToken = generateToken(payload.email, "1h");
    const newRefresh = generateToken(payload.email, "7d");
    return { ok: true, tokens: { accessToken, refreshToken: newRefresh } };
  } catch {
    return rep.code(401).send({ error: "Invalid refresh token." });
  }
});

function safeUser(user) {
  const { passwordHash, ...rest } = user;
  return rest;
}

// ----------------- routes: categories, quotes, search
app.get("/api/categories", async () => ({ ok: true, categories }));

app.get("/api/quote", async (req, rep) => {
  // random, cu filtrare premium dacă nu e PRO
  const email = tryGetEmail(req);
  const user = email ? users.get(email) : null;
  const isPro = user && user.subscription?.status === "active" && user.subscription?.tier === "pro";

  const pool = QUOTES.filter(q => isPro ? true : !q.premium);
  const q = pool[Math.floor(Math.random() * pool.length)];
  stats.quotes++;
  return { ok: true, quote: q };
});

app.get("/api/collections", async () => {
  // public metadata — fără conținut premium
  return { ok: true, collections: PREMIUM_COLLECTIONS.map(c => ({ id: c.id, name: c.name, premium: true })) };
});

app.get("/api/collections/premium/:id", { preHandler: [authMiddleware, requirePro] }, async (req, rep) => {
  const { id } = req.params;
  const col = PREMIUM_COLLECTIONS.find(c => c.id === id);
  if (!col) return rep.code(404).send({ error: "Collection not found" });
  const items = QUOTES.filter(q => col.items.includes(q.id));
  return { ok: true, id: col.id, name: col.name, items };
});

app.get("/api/search", async (req, rep) => {
  const q = String(req.query?.q || "").toLowerCase().trim();
  if (!q) return { ok: true, results: [] };
  const results = QUOTES.filter(it =>
    it.text.toLowerCase().includes(q) ||
    it.author.toLowerCase().includes(q) ||
    String(it.year).includes(q)
  );
  return { ok: true, results };
});

// ----------------- routes: favorites (basic)
app.post("/api/favorites/toggle", { preHandler: [authMiddleware] }, async (req, rep) => {
  const { quoteId } = req.body || {};
  if (!quoteId) return rep.code(400).send({ error: "quoteId required" });
  const user = users.get(req.user.email);
  user.favorites = user.favorites || [];
  const idx = user.favorites.indexOf(quoteId);
  if (idx === -1) user.favorites.push(quoteId);
  else user.favorites.splice(idx, 1);
  stats.favorites++;
  pushAudit({ type: "favorite:toggle", email: req.user.email, quoteId });
  return { ok: true, favorites: user.favorites };
});

app.get("/api/favorites", { preHandler: [authMiddleware] }, async (req, rep) => {
  const user = users.get(req.user.email);
  const items = (user.favorites || []).map(id => QUOTES.find(q => q.id === id)).filter(Boolean);
  return { ok: true, items };
});

// ----------------- nou: ruta pentru AI quotes (free export demo)
app.get("/api/ai/export", async () => {
  return { ok: true, quotes: AI_QUOTES };
});

// ----------------- routes: translations
app.post("/api/translate", async (req, rep) => {
  const { text, targetLang = "EN" } = req.body || {};
  if (!text) return rep.code(400).send({ error: "text required" });
  const translated = await translateText(text, targetLang);
  return { ok: true, translated };
});

// ----------------- routes: notificări (FCM)  🔹 NEW
// 1) înregistrare token
app.post("/api/notify/register", { preHandler: [authMiddleware] }, async (req, rep) => {
  const { token } = req.body || {};
  if (!token) return rep.code(400).send({ error: "FCM token required" });
  const set = pushTokens.get(req.user.email) || new Set();
  set.add(token);
  pushTokens.set(req.user.email, set);
  pushAudit({ type: "notify:register", email: req.user.email });
  return { ok: true, count: set.size };
});

// 2) trimitere test notificare către userul curent
app.post("/api/notify/test", { preHandler: [authMiddleware] }, async (req, rep) => {
  const tokens = Array.from(pushTokens.get(req.user.email) || []);
  if (!tokens.length) return rep.code(400).send({ error: "No tokens for user" });
  if (!FCM_SERVER_KEY) return rep.code(500).send({ error: "FCM not configured" });
  try {
    const res = await fetchWithRetry("https://fcm.googleapis.com/fcm/send", {
      method: "POST",
      headers: { "Content-Type": "application/json", "Authorization": `key=${FCM_SERVER_KEY}` },
      body: JSON.stringify({
        registration_ids: tokens,
        notification: { title: "SoulLift", body: "Test notification ✅" },
        data: { type: "test", ts: Date.now() }
      })
    }, { label: "fcm:send" });
    const data = await res.json();
    return { ok: true, result: data };
  } catch (e) { pushErr(e); return rep.code(500).send({ error: "FCM send failed" }); }
});

// 3) broadcast minimal (admin-ish) – trimite tuturor PRO (exemplu)
app.post("/api/notify/broadcast", async (req, rep) => {
  const { title="SoulLift", body="Hello!", proOnly=true } = req.body || {};
  if (!FCM_SERVER_KEY) return rep.code(500).send({ error: "FCM not configured" });
  const batches = [];
  for (const [email, set] of pushTokens.entries()) {
    const user = users.get(email);
    if (proOnly && !(user?.subscription?.status==="active" && user?.subscription?.tier==="pro")) continue;
    const tokens = Array.from(set || []);
    if (!tokens.length) continue;
    batches.push(tokens);
  }
  if (!batches.length) return { ok: true, sent: 0 };
  let sent = 0;
  for (const tokens of batches) {
    try {
      const res = await fetchWithRetry("https://fcm.googleapis.com/fcm/send", {
        method: "POST",
        headers: { "Content-Type": "application/json", "Authorization": `key=${FCM_SERVER_KEY}` },
        body: JSON.stringify({ registration_ids: tokens, notification: { title, body }, data: { type: "broadcast", ts: Date.now() } })
      }, { label: "fcm:broadcast" });
      await res.json(); sent += tokens.length;
      await sleep(200);
    } catch(e){ pushErr(e); }
  }
  pushAudit({ type: "notify:broadcast", count: sent });
  return { ok: true, sent };
});

// ----------------- routes: billing (Stripe Checkout + Portal + Webhook)

// Creează sesiune Stripe Checkout (abonament)
app.post("/api/billing/checkout", { preHandler: [authMiddleware] }, async (req, rep) => {
  const { plan = "monthly", successPath = "/pro/success", cancelPath = "/pro/cancel" } = req.body || {};
  const user = users.get(req.user.email);
  if (!user) return rep.code(401).send({ error: "Unauthorized" });

  const priceId = plan === "yearly" && STRIPE_PRICE_ID_YEARLY ? STRIPE_PRICE_ID_YEARLY : STRIPE_PRICE_ID_MONTHLY;
  if (!priceId) return rep.code(500).send({ error: "Price not configured." });

  // creăm customer dacă nu există
  let customerId = user.subscription?.stripeCustomerId;
  if (!customerId) {
    const customer = await stripe.customers.create({
      email: user.email,
      metadata: { app: "SoulLift" }
    });
    customerId = customer.id;
    user.subscription.stripeCustomerId = customerId;
  }

  const session = await stripe.checkout.sessions.create({
    mode: "subscription",
    customer: customerId,
    line_items: [{ price: priceId, quantity: 1 }],
    allow_promotion_codes: true,
    success_url: `${FRONTEND_URL}${successPath}?session_id={CHECKOUT_SESSION_ID}`,
    cancel_url: `${FRONTEND_URL}${cancelPath}`,
    billing_address_collection: "auto"
  });

  stats.checkouts++;
  pushAudit({ type: "checkout:create", email: user.email, plan });
  return { ok: true, url: session.url };
});

// Link către Customer Portal (gestionare abonament)
app.get("/api/billing/portal", { preHandler: [authMiddleware] }, async (req, rep) => {
  const user = users.get(req.user.email);
  if (!user?.subscription?.stripeCustomerId) {
    return rep.code(400).send({ error: "No Stripe customer for this user." });
  }
  const portal = await stripe.billingPortal.sessions.create({
    customer: user.subscription.stripeCustomerId,
    return_url: `${FRONTEND_URL}/account`
  });
  return { ok: true, url: portal.url };
});

// Webhook Stripe — folosește rawBody (plugin fastify-raw-body)
app.route({
  method: "POST",
  url: "/api/stripe/webhook",
  config: { rawBody: true },
  handler: async (req, rep) => {
    const sig = req.headers["stripe-signature"];
    let event;
    try {
      event = stripe.webhooks.constructEvent(req.rawBody, sig, STRIPE_WEBHOOK_SECRET);
    } catch (err) {
      app.log.error("Stripe webhook signature error", err);
      Sentry?.captureException?.(err);
      pushErr(err);
      return rep.code(400).send({ error: `Webhook Error: ${err.message}` });
    }

    stats.webhookEvents++;

    // Procesează evenimente cheie
    switch (event.type) {
      case "checkout.session.completed": {
        const session = event.data.object;
        const customerId = session.customer;
        const subId = session.subscription;

        const user = findUserByCustomerOrEmail(customerId, session.customer_details?.email);
        if (user) {
          user.subscription.status = "active";
          user.subscription.tier = "pro";
          user.subscription.stripeCustomerId = customerId;
          user.subscription.stripeSubId = subId;
          try {
            const sub = await stripe.subscriptions.retrieve(subId);
            if (sub?.current_period_end) {
              user.subscription.currentPeriodEnd = sub.current_period_end * 1000;
            }
          } catch(e){ pushErr(e); }
          app.log.info(`✅ Activated PRO for ${user.email}`);
          pushAudit({ type: "subscription:activated", email: user.email });
        }
        break;
      }
      case "customer.subscription.updated":
      case "customer.subscription.created": {
        const sub = event.data.object;
        const user = findUserByCustomer(sub.customer);
        if (user) {
          user.subscription.stripeSubId = sub.id;
          user.subscription.currentPeriodEnd = (sub.current_period_end || 0) * 1000;
          const statusMap = {
            active: "active",
            trialing: "active",
            past_due: "past_due",
            canceled: "canceled",
            unpaid: "past_due",
            incomplete: "inactive",
            incomplete_expired: "inactive"
          };
          user.subscription.status = statusMap[sub.status] || "inactive";
          user.subscription.tier = user.subscription.status === "active" ? "pro" : "free";
          app.log.info(`🔄 Subscription update for ${user.email}: ${sub.status}`);
          pushAudit({ type: "subscription:update", email: user.email, status: sub.status });
        }
        break;
      }
      case "customer.subscription.deleted": {
        const sub = event.data.object;
        const user = findUserByCustomer(sub.customer);
        if (user) {
          user.subscription.status = "canceled";
          user.subscription.tier = "free";
          user.subscription.currentPeriodEnd = null;
          app.log.info(`🪪 Subscription canceled for ${user.email}`);
          pushAudit({ type: "subscription:canceled", email: user.email });
        }
        break;
      }
      default:
        app.log.debug(`Unhandled Stripe event: ${event.type}`);
    }

    return { received: true };
  }
});

function findUserByCustomerOrEmail(customerId, email) {
  for (const u of users.values()) {
    if (u.subscription?.stripeCustomerId === customerId) return u;
  }
  if (email && users.has(email)) return users.get(email);
  return null;
}
function findUserByCustomer(customerId) {
  for (const u of users.values()) {
    if (u.subscription?.stripeCustomerId === customerId) return u;
  }
  return null;
}

// ----------------- routes: stats (basic)
app.get("/api/stats", async () => ({ ok: true, stats, audit: audit.slice(-20) })); // 🔹 include ultimele evenimente

// ----------------- small UX helpers (quality-of-life)
function tryGetEmail(req) {
  try {
    const auth = req.headers.authorization;
    if (!auth) return null;
    const token = auth.split(" ")[1];
    const payload = jwt.verify(token, JWT_SECRET);
    return payload.email || null;
  } catch {
    return null;
  }
}

// 🔹 NEW: global onError hook → colectează erorile și le trimite în Sentry
app.setErrorHandler((err, req, rep) => {
  pushErr(err);
  Sentry?.captureException?.(err);
  app.log.error({ err }, "Unhandled error");
  rep.code(500).send({ error: "Internal Server Error" });
});

// ----------------- start
try {
  await app.listen({ port: PORT, host: "0.0.0.0" });
  app.log.info(`SoulLift listening on :${PORT}`);
} catch (err) {
  pushErr(err);
  app.log.error(err);
  process.exit(1);
}
