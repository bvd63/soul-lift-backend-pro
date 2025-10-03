// src/utils/memoryCache.js - Sistem de cache avansat pentru răspunsuri AI
// Implementează LRU (Least Recently Used) cache cu prioritizare și statistici

class AdvancedCache {
  constructor(maxSize = 1000) {
    this.store = new Map();
    this.maxSize = maxSize;
    this.stats = {
      hits: 0,
      misses: 0,
      aiHits: 0,
      aiMisses: 0,
      evictions: 0
    };
    this.timeouts = new Map();
    this.accessTimes = new Map();
    this.priorities = new Map(); // 1-10, 10 fiind cea mai mare prioritate
  }

  // Setează o valoare în cache cu TTL și prioritate opționale
  set(key, value, options = {}) {
    const { ttlMs = 0, priority = 5, isAIResponse = false } = options;
    
    // Verifică dacă trebuie să eliberăm spațiu
    if (this.store.size >= this.maxSize && !this.store.has(key)) {
      this._evictLRU();
    }
    
    // Stochează valoarea și metadatele
    this.store.set(key, { value, isAIResponse });
    this.accessTimes.set(key, Date.now());
    this.priorities.set(key, priority);
    
    // Setează timeout pentru TTL
    if (ttlMs > 0) {
      // Curăță timeout-ul existent dacă există
      if (this.timeouts.has(key)) {
        clearTimeout(this.timeouts.get(key));
      }
      
      const timeoutId = setTimeout(() => {
        this.del(key);
      }, ttlMs);
      
      if (timeoutId.unref) timeoutId.unref();
      this.timeouts.set(key, timeoutId);
    }
    
    return true;
  }

  // Obține o valoare din cache și actualizează statisticile
  get(key, updateStats = true) {
    const entry = this.store.get(key);
    
    if (entry) {
      if (updateStats) {
        this.stats.hits++;
        if (entry.isAIResponse) this.stats.aiHits++;
      }
      
      // Actualizează timpul de acces pentru LRU
      this.accessTimes.set(key, Date.now());
      return entry.value;
    }
    
    if (updateStats) {
      this.stats.misses++;
      // Presupunem că este o cerere AI dacă cheia începe cu "ai:"
      if (key.startsWith('ai:')) this.stats.aiMisses++;
    }
    
    return undefined;
  }

  // Șterge o valoare din cache
  del(key) {
    // Curăță timeout-ul asociat
    if (this.timeouts.has(key)) {
      clearTimeout(this.timeouts.get(key));
      this.timeouts.delete(key);
    }
    
    this.accessTimes.delete(key);
    this.priorities.delete(key);
    return this.store.delete(key);
  }

  // Golește cache-ul complet
  clear() {
    // Curăță toate timeout-urile
    for (const timeoutId of this.timeouts.values()) {
      clearTimeout(timeoutId);
    }
    
    this.store.clear();
    this.timeouts.clear();
    this.accessTimes.clear();
    this.priorities.clear();
    return true;
  }

  // Obține statisticile cache-ului
  getStats() {
    return {
      ...this.stats,
      size: this.store.size,
      maxSize: this.maxSize,
      hitRate: this.stats.hits / (this.stats.hits + this.stats.misses || 1),
      aiHitRate: this.stats.aiHits / (this.stats.aiHits + this.stats.aiMisses || 1)
    };
  }

  // Resetează statisticile
  resetStats() {
    this.stats = {
      hits: 0,
      misses: 0,
      aiHits: 0,
      aiMisses: 0,
      evictions: 0
    };
  }

  // Elimină elementul cel mai puțin recent utilizat, ținând cont de prioritate
  _evictLRU() {
    let oldestKey = null;
    let oldestTime = Infinity;
    let lowestPriority = Infinity;
    
    // Găsește elementul cu cea mai mică prioritate și cel mai vechi timp de acces
    for (const [key, time] of this.accessTimes.entries()) {
      const priority = this.priorities.get(key) || 0;
      
      // Dacă prioritatea este mai mică sau egală și timpul este mai vechi
      if (priority < lowestPriority || (priority === lowestPriority && time < oldestTime)) {
        lowestPriority = priority;
        oldestTime = time;
        oldestKey = key;
      }
    }
    
    if (oldestKey) {
      this.del(oldestKey);
      this.stats.evictions++;
    }
  }

  // Preîncălzește cache-ul cu valori cunoscute
  preload(entries) {
    for (const [key, value, options] of entries) {
      this.set(key, value, options);
    }
  }
}

// Instanță singleton
const cache = new AdvancedCache();

// Funcții de export compatibile cu versiunea anterioară
function set(key, value, ttlMs = 0) {
  return cache.set(key, value, { ttlMs });
}

function get(key) {
  return cache.get(key);
}

function del(key) {
  return cache.del(key);
}

function clear() {
  return cache.clear();
}

// Funcții noi pentru cache-ul avansat
function setAdvanced(key, value, options = {}) {
  return cache.set(key, value, options);
}

function getStats() {
  return cache.getStats();
}

function resetStats() {
  return cache.resetStats();
}

function preload(entries) {
  return cache.preload(entries);
}

export default { 
  get, 
  set, 
  del, 
  clear,
  // Funcții avansate
  setAdvanced,
  getStats,
  resetStats,
  preload
};
