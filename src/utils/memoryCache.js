// src/utils/memoryCache.js (ESM)

// Capacitate maximă cache (500 chei)
const MAX_KEYS = 500;
const mem = new Map();

const now = () => Date.now();

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

const cache = { get, set, del };

export { get, set, del };
export default cache;
