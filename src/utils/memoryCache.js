// src/utils/memoryCache.js
const store = new Map();

function set(key, value, ttlMs = 0) {
  store.set(key, value);
  if (ttlMs > 0) {
    const t = setTimeout(() => store.delete(key), ttlMs);
    if (t.unref) t.unref();
  }
}
function get(key) { return store.get(key); }
function del(key) { return store.delete(key); }
function clear() { store.clear(); }

export default { get, set, del, clear };
