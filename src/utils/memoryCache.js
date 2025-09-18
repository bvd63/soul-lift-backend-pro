// src/utils/memoryCache.js

// Cache simplu în memorie, se golește la restart
const MAX_KEYS = 500;
const mem = new Map();

function now() { return Date.now(); }

function pruneIfTooBig() {
  while (mem.size > MAX_KEYS) {
    const oldestKey = mem.keys().next().value;
    mem.delete(oldestKey);
  }
}

function get(key) {
  const hit = mem.get(key);
  if (!hit) return null;
  if (hit.expiresAt <= now()) {
    mem.delete(key);
    return null;
  }
  return hit.value;
}

function set(key, value, ttlSeconds) {
  const expiresAt = now() + ttlSeconds * 1000;
  mem.set(key, { value, expiresAt });
  pruneIfTooBig();
}

function del(key) {
  mem.delete(key);
}

module.exports = { get, set, del };
