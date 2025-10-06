// src/services/redisClient.js — thin wrapper over cache util to standardize Redis usage
import cache from '../utils/cache.js';

async function get(key) {
  return cache.get(key);
}

async function set(key, value, ttlSec = 3600) {
  return cache.set(key, value, ttlSec);
}

async function del(key) {
  return cache.del(key);
}

function isUp() {
  return cache.isRedisConnected();
}

export default { get, set, del, isUp };
