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

import cache from "./src/utils/memoryCache.js";

// ----------------- core setup
const isProd = process.env.NODE_ENV === "production";
const app = Fastify({ logger: { level: isProd ? "info" : "debug" } });

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "soul-lift-secret";

// OpenAI / DeepL (traduceri)
const OPENAI_KEY = process.env.OPENAI_API_KEY || "";
const DEEPL_KEY = process.env.DEEPL_API_KEY || "";
const DEEPL_ENDPOINT = "https://api-free.deepl.com";

// ----------------- plugins
await app.register(cors, { origin: true });
await app.register(helmet, { global: true });
await app.register(rateLimit, { max: 120, timeWindow: 60_000 });
await app.register(compress);
await app.register(swagger, {
  openapi: { info: { title: "SoulLift API", version: "6.0.0" } },
});
await app.register(swaggerUI, { routePrefix: "/docs" });
await app.register(metrics, { endpoint: "/metrics", defaultMetrics: { enabled: true } });

// ----------------- in-memory stores (MVP)
const users = new Map(); // email -> { password(hash), premium, favorites:[{text,note?}], mood, streak, lastLogin, badges[], playlists:{name:[quotes]}, notif:{quietHours:[start,end], preferredHour}, lastActiveHour }
let stats = {
  quotes: 0,
  translations: 0,
  logins: 0,
  registers: 0,
  favorites: 0,
  playlistCreates: 0,
  shareViews: 0,
};

// ----------------- catalog / content
const categories = JSON.parse(fs.readFileSync("./categories.json", "utf-8"));

// cotație cu metadate (încredere & claritate)
const QUOTES = [
  {
    id: "q1",
    text: "Your future is created by what you do today, not tomorrow.",
    author: "Robert Kiyosaki",
    source: "Interview",
    year: 2001,
    premium: false,
  },
  {
    id: "q2",
    text: "Success is not for the lazy.",
    author: "Jim Rohn",
    source: "Seminar",
    year: 1985,
    premium: false,
  },
  {
    id: "q3",
    text: "Focus on progress, not perfection.",
    author: "Bill Gates",
    source: "Talk",
    year: 2010,
    premium: false,
  },
  {
    id: "q4",
    text: "Gratitude turns what we have into enough.",
    author: "Aesop",
    source: "Fables",
    year: -550,
    premium: true, // exemplu de conținut premium
  },
];

// colecții premium (exemplu)
const PREMIUM_COLLECTIONS = [
  { id: "stoicism", name: "Stoicism Starter", items: ["q4"] },
  { id: "deep-focus", name: "Deep Focus", items: ["q2", "q3"] },
];

// limbile afișate în aplicație (DeepL-friendly)
const SUPPORTED_LANGS = [
  "EN", "RO", "FR", "DE", "ES", "IT", "PT", "RU", "JA", "ZH", "NL", "PL", "TR"
];

// ----------------- helpers
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
function todayStr() {
  return new Date().toISOString().slice(0, 10);
}
function updateStreakOnLogin(user) {
  const last = user.lastLogin || null;
  const today = todayStr();
  if (last === today) return; // deja contorizat azi
  if (!last) {
    user.streak = 1;
  } else {
    const dLast = new Date(last);
    const dPrev = new Date(dLast.getTime() + 24 * 3600 * 1000);
    const isYesterday = dPrev.toISOString().slice(0, 10) === today;
    user.streak = isYesterday ? (user.streak || 0) + 1 : 1;
  }
  user.lastLogin = today;
  // badges simple
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
      { role: "user", content: `Translate to ${targetLang}:\n${text}` },
    ],
    temperature: 0.2,
  };
  const res = await fetch("https://api.openai.com/v1/chat/completions", {
    method: "POST",
    headers: { Authorization: `Bearer ${OPENAI_KEY}`, "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) return null;
  const data = await res.json();
  return data?.choices?.[0]?.message?.content?.trim() || null;
}
async function translateWithDeepL(text, targetLang) {
  if (!DEEPL_KEY) return null;
  const params = new URLSearchParams({
    auth_key: DEEPL_KEY,
    text,
    target_lang: String(targetLang || "EN").toUpperCase(),
  });
  const res = await fetch(`${DEEPL_ENDPOINT}/v2/translate`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: params,
  });
  if (!res.ok) return null;
  const data = await res.json();
  return data?.translations?.[0]?.text || null;
}
async function translateText(text, targetLang = "EN") {
  if (!text) return "";
  let translated = null;
  try { translated = await translateWithOpenAI(text, targetLang); } catch {}
  if (!translated) {
    try { translated = await translateWithDeepL(text, targetLang); } catch {}
  }
  if (translated && translated !== text) stats.translations++;
  return translated || text;
}

// ----------------- routes — core existente
app.get("/healthz", async () => ({ status: "ok" }));

app.get("/api/categories", async () => categories);

// random quote + optional translate + metadata
app.get("/api/quote", async (req) => {
  const lang = (req.query.lang || "EN").toUpperCase();
  const q = QUOTES[Math.floor(Math.random() * QUOTES.length)];
  const translated = await translateText(q.text, lang);
  stats.quotes++;
  return {
    ok: true,
    lang,
    quote: { id: q.id, text: q.text, author: q.author, source: q.source, year: q.year, premium: q.premium },
    translated,
  };
});

// search (experiență / căutare)
app.get("/api/search", async (req) => {
  const q = String(req.query.q || "").toLowerCase();
  if (!q) return { ok: true, results: [] };
  const results = QUOTES.filter(
    (x) => x.text.toLowerCase().includes(q) || (x.author || "").toLowerCase().includes(q)
  ).map(({ id, text, author, source, year, premium }) => ({ id, text, author, source, year, premium }));
  return { ok: true, results };
});

// offline bootstrap (experiență / offline-first)
app.get("/api/offline/bootstrap", async () => {
  return {
    ok: true,
    categories,
    topQuotes: QUOTES.slice(0, 6).map(({ id, text, author, source, year, premium }) => ({ id, text, author, source, year, premium })),
    langs: SUPPORTED_LANGS,
  };
});

// languages (localizare)
app.get("/api/languages", async () => ({ ok: true, languages: SUPPORTED_LANGS }));

// ----------------- users / auth (securitate)
app.post("/api/register", async (req, rep) => {
  const { email, password } = req.body || {};
  if (!email || !password) return rep.code(400).send({ error: "Missing email or password" });
  if (users.has(email)) return rep.code(400).send({ error: "User already exists" });

  const hash = await bcrypt.hash(password, 10);
  users.set(email, {
    password: hash,
    premium: false,
    favorites: [],
    mood: "focus",
    streak: 0,
    lastLogin: null,
    badges: [],
    playlists: {}, // name -> [quotes]
    notif: { quietHours: [22, 7], preferredHour: 9 },
    lastActiveHour: null,
  });
  stats.registers++;
  return { ok: true };
});

app.post("/api/login", async (req, rep) => {
  const { email, password } = req.body || {};
  if (!email || !password) return rep.code(400).send({ error: "Missing email or password" });

  const user = users.get(email);
  if (!user || !(await bcrypt.compare(password, user.password)))
    return rep.code(401).send({ error: "Invalid credentials" });

  updateStreakOnLogin(user);
  stats.logins++;
  const token = generateToken(email, "1h");
  const refresh = generateToken(email, "7d");
  return { ok: true, token, refresh, premium: user.premium, streak: user.streak, badges: user.badges };
});

app.post("/api/refresh", async (req, rep) => {
  const { refresh } = req.body || {};
  if (!refresh) return rep.code(400).send({ error: "Missing refresh token" });
  try {
    const decoded = jwt.verify(refresh, JWT_SECRET);
    const newToken = generateToken(decoded.email, "1h");
    return { ok: true, token: newToken };
  } catch {
    return rep.code(401).send({ error: "Invalid refresh token" });
  }
});

// ----------------- mood of the day (personalizare)
app.get("/api/mood", { preHandler: authMiddleware }, async (req) => {
  const user = users.get(req.user.email);
  return { ok: true, mood: user.mood || "focus" };
});
app.post("/api/mood", { preHandler: authMiddleware }, async (req, rep) => {
  const { mood } = req.body || {};
  const allowed = ["focus", "calm", "boost", "gratitude"];
  if (!allowed.includes(mood)) return rep.code(400).send({ error: "Invalid mood" });
  const user = users.get(req.user.email);
  user.mood = mood;
  return { ok: true, mood };
});

// ----------------- streaks & badges (gamificare)
app.get("/api/badges", { preHandler: authMiddleware }, async (req) => {
  const user = users.get(req.user.email);
  return { ok: true, streak: user.streak || 0, badges: user.badges || [] };
});

// ----------------- favorites + reflections
app.get("/api/favorites", { preHandler: authMiddleware }, async (req) => {
  const user = users.get(req.user.email);
  return { ok: true, favorites: user.favorites };
});
app.post("/api/favorites", { preHandler: authMiddleware }, async (req, rep) => {
  const { text, note } = req.body || {};
  if (!text) return rep.code(400).send({ error: "Missing quote" });
  const user = users.get(req.user.email);
  user.favorites.push(note ? { text, note } : { text });
  stats.favorites++;
  return { ok: true };
});
app.delete("/api/favorites", { preHandler: authMiddleware }, async (req, rep) => {
  const { text } = req.body || {};
  if (!text) return rep.code(400).send({ error: "Missing quote" });
  const user = users.get(req.user.email);
  user.favorites = user.favorites.filter((q) => (typeof q === "string" ? q !== text : q.text !== text));
  return { ok: true };
});

// ----------------- playlists (colecții personale)
app.get("/api/playlists", { preHandler: authMiddleware }, async (req) => {
  const user = users.get(req.user.email);
  return { ok: true, playlists: user.playlists || {} };
});
app.post("/api/playlists", { preHandler: authMiddleware }, async (req, rep) => {
  const { name } = req.body || {};
  if (!name) return rep.code(400).send({ error: "Missing name" });
  const user = users.get(req.user.email);
  user.playlists = user.playlists || {};
  if (user.playlists[name]) return rep.code(400).send({ error: "Playlist exists" });
  user.playlists[name] = [];
  stats.playlistCreates++;
  return { ok: true };
});
app.post("/api/playlists/add", { preHandler: authMiddleware }, async (req, rep) => {
  const { name, text } = req.body || {};
  if (!name || !text) return rep.code(400).send({ error: "Missing name or text" });
  const user = users.get(req.user.email);
  if (!user.playlists?.[name]) return rep.code(404).send({ error: "Playlist not found" });
  user.playlists[name].push(text);
  return { ok: true };
});
app.post("/api/playlists/remove", { preHandler: authMiddleware }, async (req, rep) => {
  const { name, text } = req.body || {};
  if (!name || !text) return rep.code(400).send({ error: "Missing name or text" });
  const user = users.get(req.user.email);
  if (!user.playlists?.[name]) return rep.code(404).send({ error: "Playlist not found" });
  user.playlists[name] = user.playlists[name].filter((q) => q !== text);
  return { ok: true };
});
app.delete("/api/playlists", { preHandler: authMiddleware }, async (req, rep) => {
  const { name } = req.body || {};
  const user = users.get(req.user.email);
  if (user.playlists?.[name]) delete user.playlists[name];
  return { ok: true };
});

// ----------------- notificări (setări & ping)
app.get("/api/notifications/settings", { preHandler: authMiddleware }, async (req) => {
  const user = users.get(req.user.email);
  return { ok: true, settings: user.notif || { quietHours: [22, 7], preferredHour: 9 } };
});
app.post("/api/notifications/settings", { preHandler: authMiddleware }, async (req, rep) => {
  const { quietHours, preferredHour } = req.body || {};
  const user = users.get(req.user.email);
  if (quietHours && Array.isArray(quietHours) && quietHours.length === 2) {
    user.notif.quietHours = [Number(quietHours[0]) || 22, Number(quietHours[1]) || 7];
  }
  if (Number.isFinite(preferredHour)) user.notif.preferredHour = Number(preferredHour);
  return { ok: true, settings: user.notif };
});
// salvează ora când userul a fost activ (pt smart reminders)
app.post("/api/ping", { preHandler: authMiddleware }, async (req) => {
  const hour = new Date().getHours();
  const user = users.get(req.user.email);
  user.lastActiveHour = hour;
  return { ok: true, hour };
});

// ----------------- premium content (paywall logic de bază)
app.get("/api/collections", async () => {
  return { ok: true, collections: PREMIUM_COLLECTIONS.map(({ id, name, items }) => ({ id, name, count: items.length })) };
});
app.get("/api/collections/:id", { preHandler: authMiddleware }, async (req, rep) => {
  const { id } = req.params;
  const col = PREMIUM_COLLECTIONS.find((c) => c.id === id);
  if (!col) return rep.code(404).send({ error: "Collection not found" });
  const user = users.get(req.user.email);
  if (!user.premium) return rep.code(402).send({ error: "Premium required" });
  const items = col.items.map((qid) => QUOTES.find((q) => q.id === qid)).filter(Boolean);
  return { ok: true, collection: { id, name: col.name, items } };
});

// ----------------- share cards (SVG simplu, fără dep extra)
app.get("/api/share/:id.svg", async (req, rep) => {
  const { id } = req.params;
  const q = QUOTES.find((x) => x.id === id);
  if (!q) return rep.code(404).send("Not found");
  stats.shareViews++;
  rep.header("Content-Type", "image/svg+xml");
  const text = q.text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  const author = (q.author || "Unknown Author").replace(/&/g, "&amp;");
  // SVG minimal, 1200x630 (open graph)
  const svg = `
  <svg width="1200" height="630" xmlns="http://www.w3.org/2000/svg">
    <defs>
      <linearGradient id="g" x1="0" y1="0" x2="1" y2="1">
        <stop offset="0%" stop-color="#2E3192"/>
        <stop offset="100%" stop-color="#1BFFFF"/>
      </linearGradient>
    </defs>
    <rect width="1200" height="630" fill="url(#g)"/>
    <foreignObject x="80" y="80" width="1040" height="470">
      <div xmlns="http://www.w3.org/1999/xhtml" style="font-family: system-ui, -apple-system, Segoe UI, Roboto; color: white;">
        <div style="font-size:48px; line-height:1.2; font-weight:700; white-space:pre-wrap;">${text}</div>
        <div style="margin-top:28px; font-size:28px; opacity:.9;">— ${author}</div>
        <div style="position:absolute; bottom:0; right:0; font-size:20px; opacity:.8;">SoulLift</div>
      </div>
    </foreignObject>
  </svg>`;
  return rep.send(svg.trim());
});

// ----------------- privacy (export / delete)
app.get("/api/privacy/export", { preHandler: authMiddleware }, async (req) => {
  const user = users.get(req.user.email);
  const exportData = { email: req.user.email, ...user };
  return { ok: true, data: exportData };
});
app.post("/api/privacy/delete", { preHandler: authMiddleware }, async (req) => {
  users.delete(req.user.email);
  return { ok: true };
});

// ----------------- subscription simulate + verify purchase (Google Play placeholder)
app.get("/api/subscription", { preHandler: authMiddleware }, async (req) => {
  const user = users.get(req.user.email);
  return { ok: true, premium: user.premium };
});
// verificare simulată a achiziției (viitor: apel Google Play Developer API)
app.post("/api/verify-purchase", { preHandler: authMiddleware }, async (req, rep) => {
  const { productId, purchaseToken } = req.body || {};
  if (!productId || !purchaseToken) return rep.code(400).send({ error: "Missing productId or purchaseToken" });
  const user = users.get(req.user.email);
  // simulăm că e valid:
  user.premium = true;
  return { ok: true, premium: true, productId };
});

// ----------------- onboarding & referral (growth)
app.post("/api/onboarding/save", { preHandler: authMiddleware }, async (req) => {
  const user = users.get(req.user.email);
  const { language, mood, preferredHour } = req.body || {};
  if (language && SUPPORTED_LANGS.includes(language)) user.uiLang = language;
  if (mood) user.mood = mood;
  if (Number.isFinite(preferredHour)) user.notif.preferredHour = Number(preferredHour);
  return { ok: true };
});

// referral simplu în memorie
const referrals = new Map(); // code -> emailCreator
function makeCode() { return Math.random().toString(36).slice(2, 8).toUpperCase(); }
app.post("/api/referral/create", { preHandler: authMiddleware }, async (req) => {
  const code = makeCode();
  referrals.set(code, req.user.email);
  return { ok: true, code };
});
app.post("/api/referral/redeem", { preHandler: authMiddleware }, async (req, rep) => {
  const { code } = req.body || {};
  if (!code || !referrals.has(code)) return rep.code(400).send({ error: "Invalid code" });
  const inviter = referrals.get(code);
  referrals.delete(code);
  // bonus simplu: amândoi primesc premium 7 zile (simulat)
  const you = users.get(req.user.email);
  you.premium = true;
  const invUser = users.get(inviter);
  if (invUser) invUser.premium = true;
  return { ok: true, premium: true, invitedBy: inviter };
});

// ----------------- stats
app.get("/api/stats", async () => stats);

// ----------------- start
try {
  await app.listen({ port: PORT, host: "0.0.0.0" });
  app.log.info(`SoulLift listening on :${PORT}`);
} catch (err) {
  app.log.error(err);
  process.exit(1);
}
