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
import cron from "node-cron";   // 👈 pentru AI quotes automate

import cache from "./src/utils/memoryCache.js";

// ----------------- core setup
const isProd = process.env.NODE_ENV === "production";
const app = Fastify({ logger: { level: isProd ? "info" : "debug" } });

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "soul-lift-secret";

// OpenAI / DeepL
const OPENAI_KEY = process.env.OPENAI_API_KEY || "";
const DEEPL_KEY = process.env.DEEPL_API_KEY || "";
const DEEPL_ENDPOINT = "https://api-free.deepl.com";

// ----------------- plugins
await app.register(cors, { origin: true });
await app.register(helmet, { global: true });
await app.register(rateLimit, { max: 120, timeWindow: 60_000 });
await app.register(compress);
await app.register(swagger, {
  openapi: { info: { title: "SoulLift API", version: "7.0.0" } },
});
await app.register(swaggerUI, { routePrefix: "/docs" });
await app.register(metrics, { endpoint: "/metrics", defaultMetrics: { enabled: true } });

// ----------------- in-memory stores
const users = new Map();
let stats = {
  quotes: 0,
  translations: 0,
  logins: 0,
  registers: 0,
  favorites: 0,
  playlistCreates: 0,
  shareViews: 0,
  aiQuotesGenerated: 0,   // 👈 nou
};

// ----------------- catalog / content
const categories = JSON.parse(fs.readFileSync("./categories.json", "utf-8"));
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
const SUPPORTED_LANGS = ["EN","RO","FR","DE","ES","IT","PT","RU","JA","ZH","NL","PL","TR"];

// ----------------- AI Quotes setup
let AI_QUOTES = [];

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
  const res = await fetch("https://api.openai.com/v1/chat/completions", {
    method: "POST",
    headers: { Authorization: `Bearer ${OPENAI_KEY}`, "Content-Type": "application/json" },
    body: JSON.stringify(body)
  });
  if (!res.ok) return null;
  const data = await res.json();
  return data?.choices?.[0]?.message?.content?.trim() || null;
}

async function generateBatch(count = 10) {
  const list = [];
  for (let i = 0; i < count; i++) {
    try {
      const q = await generateAIQuote();
      if (q) list.push({ text: q, createdAt: Date.now() });
    } catch {}
    await new Promise(r => setTimeout(r, 1200));
  }
  AI_QUOTES = list;
  stats.aiQuotesGenerated += list.length;
  return list;
}

// rulează la pornire
await generateBatch(10);

// rulează zilnic la ora 06:00
cron.schedule("0 6 * * *", async () => {
  console.log("⏰ Cron: generating AI quotes...");
  await generateBatch(10);
});

// ----------------- helpers (auth, jwt, streaks)
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
  const res = await fetch("https://api.openai.com/v1/chat/completions", {
    method: "POST",
    headers: { Authorization: `Bearer ${OPENAI_KEY}`, "Content-Type": "application/json" },
    body: JSON.stringify(body)
  });
  if (!res.ok) return null;
  const data = await res.json();
  return data?.choices?.[0]?.message?.content?.trim() || null;
}
async function translateWithDeepL(text, targetLang) {
  if (!DEEPL_KEY) return null;
  const params = new URLSearchParams({ auth_key: DEEPL_KEY, text, target_lang: String(targetLang||"EN").toUpperCase() });
  const res = await fetch(`${DEEPL_ENDPOINT}/v2/translate`, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: params });
  if (!res.ok) return null;
  const data = await res.json();
  return data?.translations?.[0]?.text || null;
}
async function translateText(text, targetLang="EN") {
  if (!text) return "";
  let translated = null;
  try { translated = await translateWithOpenAI(text, targetLang); } catch {}
  if (!translated) { try { translated = await translateWithDeepL(text, targetLang); } catch {} }
  if (translated && translated!==text) stats.translations++;
  return translated || text;
}

// ----------------- routes existente
// !!! aici păstrezi absolut tot ce ai deja: healthz, categories, quote, search, offline/bootstrap,
// languages, register/login/refresh, mood, badges, favorites, playlists,
// notifications, ping, collections, share, privacy, subscription, onboarding, referral, stats etc.

// ----------------- nou: ruta pentru AI quotes
app.get("/api/ai/export", async () => {
  return { ok: true, quotes: AI_QUOTES };
});

// ----------------- start
try {
  await app.listen({ port: PORT, host: "0.0.0.0" });
  app.log.info(`SoulLift listening on :${PORT}`);
} catch (err) {
  app.log.error(err);
  process.exit(1);
}
