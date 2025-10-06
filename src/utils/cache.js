// src/utils/cache.js — Redis cache cu fallback la memoryCache + suport Upstash REST
import memoryCache from './memoryCache.js';
import fetch from 'node-fetch';

let redisClient = null;
let redisReady = false;

// Upstash REST mode
let restMode = false;
let restUrl = '';
let restToken = '';
let restReady = false;

async function initRedis(redisUrl) {
  if (!redisUrl) return false;
  // Detectăm Upstash REST (HTTPS) vs client Redis clasic (redis://, rediss://)
  const isHttp = /^https?:\/\//.test(redisUrl);
  if (isHttp) {
    restMode = true;
    restUrl = redisUrl.replace(/\/$/, '');
    restToken = process.env.UPSTASH_REDIS_REST_TOKEN || '';
    try {
      const r = await fetch(`${restUrl}/PING`, { headers: restToken ? { Authorization: `Bearer ${restToken}` } : {} });
      const t = await r.text();
      restReady = r.ok && /PONG/i.test(t);
      if (!restReady) throw new Error(`Upstash PING failed: ${r.status}`);
      return true;
    } catch (e) {
      console.warn('Upstash REST indisponibil, folosim cache local:', e?.message || e);
      restReady = false;
      return false;
    }
  }

  try {
    const { createClient } = await import('redis');
    // Suport Redis Enterprise Cloud: username/parolă și TLS
    const isSecure = /^rediss:\/\//.test(redisUrl) || String(process.env.REDIS_TLS || '').toLowerCase() === 'true';
    const username = process.env.REDIS_USERNAME || undefined;
    const password = process.env.REDIS_PASSWORD || undefined;
    const clientOpts = { url: redisUrl };
    if (username) clientOpts.username = username;
    if (password) clientOpts.password = password;
    if (isSecure) clientOpts.socket = { tls: true };

    redisClient = createClient(clientOpts);
    redisClient.on('error', (err) => {
      redisReady = false;
      console.error('Redis error:', err?.message || err);
    });
    redisClient.on('ready', () => { redisReady = true; });
    await redisClient.connect();
    redisReady = true;
    return true;
  } catch (e) {
    console.warn('Redis indisponibil, folosim cache local:', e?.message || e);
    redisClient = null;
    redisReady = false;
    return false;
  }
}

async function get(key) {
  // Upstash REST
  if (restMode && restReady) {
    try {
      const r = await fetch(`${restUrl}/GET/${encodeURIComponent(key)}`, { headers: restToken ? { Authorization: `Bearer ${restToken}` } : {} });
      if (!r.ok) return null;
      const txt = await r.text();
      if (txt === 'null' || txt === '') return null;
      try { return JSON.parse(txt); } catch { return txt; }
    } catch (e) {
      console.warn('Upstash GET fail:', e?.message || e);
      return memoryCache.get(key);
    }
  }
  // Redis client
  if (redisClient && redisReady) {
    const v = await redisClient.get(key);
    if (v == null) return null;
    try { return JSON.parse(v); } catch { return v; }
  }
  return memoryCache.get(key);
}

async function set(key, value, ttlSec) {
  const v = typeof value === 'string' ? value : JSON.stringify(value);
  // Upstash REST
  if (restMode && restReady) {
    try {
      const url = ttlSec && ttlSec > 0
        ? `${restUrl}/SET/${encodeURIComponent(key)}/${encodeURIComponent(v)}?EX=${ttlSec}`
        : `${restUrl}/SET/${encodeURIComponent(key)}/${encodeURIComponent(v)}`;
      const r = await fetch(url, { headers: restToken ? { Authorization: `Bearer ${restToken}` } : {} });
      if (!r.ok) throw new Error(`Upstash SET failed: ${r.status}`);
      return true;
    } catch (e) {
      console.warn('Upstash SET fail, fallback mem:', e?.message || e);
    }
  }
  // Redis client
  if (redisClient && redisReady) {
    if (ttlSec && ttlSec > 0) {
      await redisClient.set(key, v, { EX: ttlSec });
    } else {
      await redisClient.set(key, v);
    }
    return true;
  }
  memoryCache.set(key, value, ttlSec ? ttlSec * 1000 : undefined);
  return true;
}

// Try acquire a lock: return true if acquired, false otherwise
async function tryLock(key, ttlSec = 60) {
  // Upstash REST
  if (restMode && restReady) {
    try {
      const cmd = `${restUrl}/SET/${encodeURIComponent(key)}/${encodeURIComponent('1')}?NX=true&EX=${Math.max(1, ttlSec)}`;
      const r = await fetch(cmd, { headers: restToken ? { Authorization: `Bearer ${restToken}` } : {} });
      if (!r.ok) return false;
      const txt = await r.text();
      return /(OK|OK\n|OK\r\n)/i.test(txt) || /OK/i.test(txt) || txt === 'OK';
    } catch (e) {
      return false;
    }
  }

  if (redisClient && redisReady) {
    try {
      const res = await redisClient.set(key, '1', { NX: true, EX: Math.max(1, ttlSec) });
      return res === 'OK' || res === true;
    } catch (e) { return false; }
  }
  // fallback: use memory cache with check
  if (memoryCache.get(key)) return false;
  memoryCache.set(key, '1', ttlSec * 1000);
  return true;
}

async function releaseLock(key) {
  try {
    if (restMode && restReady) {
      await fetch(`${restUrl}/DEL/${encodeURIComponent(key)}`, { headers: restToken ? { Authorization: `Bearer ${restToken}` } : {} });
      return true;
    }
    if (redisClient && redisReady) {
      await redisClient.del(key);
      return true;
    }
    memoryCache.del(key);
    return true;
  } catch (e) { return false; }
}

  // Helper to set with a default TTL (in seconds)
  async function setWithDefault(key, value, ttlSec = 3600) {
    const t = typeof ttlSec === 'number' && ttlSec > 0 ? ttlSec : 3600;
    return set(key, value, t);
  }

async function del(key) {
  // Upstash REST
  if (restMode && restReady) {
    try {
      const r = await fetch(`${restUrl}/DEL/${encodeURIComponent(key)}`, { headers: restToken ? { Authorization: `Bearer ${restToken}` } : {} });
      if (!r.ok) throw new Error(`Upstash DEL failed: ${r.status}`);
      return true;
    } catch (e) {
      console.warn('Upstash DEL fail, fallback mem:', e?.message || e);
    }
  }
  // Redis client
  if (redisClient && redisReady) {
    await redisClient.del(key);
    return true;
  }
  memoryCache.del(key);
  return true;
}

function isRedisConnected() { return !!(redisClient && redisReady) || !!restReady; }

// Backwards-compatible quick health check alias
function isUp() { return isRedisConnected(); }

async function quit() {
  if (redisClient) { await redisClient.quit(); redisReady = false; }
  // Upstash REST nu necesită închidere
}

export default { initRedis, get, set, setWithDefault, del, isRedisConnected, isUp, tryLock, releaseLock, quit };
