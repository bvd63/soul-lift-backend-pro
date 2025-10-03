// src/utils/apiRetry.js - Sistem robust de retry pentru apeluri API externe
// Oferă mecanisme avansate de reîncercare pentru toate apelurile externe

/**
 * ApiRetry - Sistem de reîncercare pentru apeluri API externe
 * 
 * Funcționalități:
 * - Reîncercări cu backoff exponențial
 * - Gestionare inteligentă a erorilor
 * - Circuit breaker pentru prevenirea supraîncărcării serviciilor externe
 * - Logging detaliat al încercărilor și erorilor
 * - Suport pentru timeout configurabil
 */

// Importuri necesare
import fetch from 'node-fetch';
import { AbortController } from 'node-fetch/externals';
import memoryCache from './memoryCache.js';

// Configurare implicită
const DEFAULT_CONFIG = {
  maxRetries: 3,
  initialDelay: 300,
  maxDelay: 10000,
  backoffFactor: 2,
  timeout: 30000,
  retryStatusCodes: [408, 429, 500, 502, 503, 504],
  retryMethods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
  useCircuitBreaker: true,
  circuitBreakerThreshold: 5,
  circuitBreakerResetTimeout: 30000,
  cacheSuccessfulResponses: false,
  cacheTTL: 60000,
  logRetries: true
};

// Starea circuit breaker-ului pentru fiecare endpoint
const circuitBreakers = new Map();

/**
 * Funcție pentru apeluri API cu reîncercări și circuit breaker
 * @param {string} url - URL-ul pentru apel
 * @param {Object} options - Opțiuni pentru fetch
 * @param {Object} retryConfig - Configurare pentru reîncercări (opțional)
 * @returns {Promise<Object>} - Răspunsul API
 */
async function fetchWithRetry(url, options = {}, retryConfig = {}) {
  // Combinăm configurarea implicită cu cea specificată
  const config = { ...DEFAULT_CONFIG, ...retryConfig };
  
  // Generăm un ID unic pentru acest apel
  const requestId = `${options.method || 'GET'}-${url}-${Date.now()}`;
  
  // Verificăm cache-ul dacă este activat
  if (config.cacheSuccessfulResponses) {
    const cacheKey = `api-${options.method || 'GET'}-${url}-${JSON.stringify(options.body || {})}`;
    const cachedResponse = memoryCache.get(cacheKey);
    if (cachedResponse) {
      console.log(`[ApiRetry] Cache hit for ${options.method || 'GET'} ${url}`);
      return cachedResponse;
    }
  }
  
  // Verificăm circuit breaker-ul
  const endpointKey = `${options.method || 'GET'}-${new URL(url).hostname}`;
  if (config.useCircuitBreaker && circuitBreakers.has(endpointKey)) {
    const breaker = circuitBreakers.get(endpointKey);
    if (breaker.state === 'open') {
      // Verificăm dacă putem reseta circuit breaker-ul
      if (Date.now() - breaker.lastFailure > config.circuitBreakerResetTimeout) {
        breaker.state = 'half-open';
        breaker.failures = 0;
        console.log(`[ApiRetry] Circuit breaker pentru ${endpointKey} a trecut în starea half-open`);
      } else {
        console.log(`[ApiRetry] Circuit breaker deschis pentru ${endpointKey}, se respinge apelul`);
        throw new Error(`Circuit breaker deschis pentru ${endpointKey}. Serviciul nu este disponibil momentan.`);
      }
    }
  } else if (config.useCircuitBreaker) {
    // Inițializăm circuit breaker-ul pentru acest endpoint
    circuitBreakers.set(endpointKey, {
      state: 'closed',
      failures: 0,
      lastFailure: 0
    });
  }
  
  // Funcție pentru actualizarea circuit breaker-ului în caz de eroare
  function updateCircuitBreakerOnFailure() {
    if (!config.useCircuitBreaker) return;
    
    const breaker = circuitBreakers.get(endpointKey);
    breaker.failures += 1;
    breaker.lastFailure = Date.now();
    
    if (breaker.failures >= config.circuitBreakerThreshold) {
      breaker.state = 'open';
      console.log(`[ApiRetry] Circuit breaker pentru ${endpointKey} a trecut în starea open după ${breaker.failures} eșecuri`);
    }
  }
  
  // Funcție pentru actualizarea circuit breaker-ului în caz de succes
  function updateCircuitBreakerOnSuccess() {
    if (!config.useCircuitBreaker) return;
    
    const breaker = circuitBreakers.get(endpointKey);
    if (breaker.state === 'half-open') {
      breaker.state = 'closed';
      breaker.failures = 0;
      console.log(`[ApiRetry] Circuit breaker pentru ${endpointKey} a trecut în starea closed după succes`);
    }
  }
  
  // Implementăm logica de reîncercare
  let attempt = 0;
  let delay = config.initialDelay;
  let lastError = null;
  
  while (attempt <= config.maxRetries) {
    const attemptStart = Date.now();
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), config.timeout);
    
    try {
      // Adăugăm signal pentru timeout
      const fetchOptions = {
        ...options,
        signal: controller.signal
      };
      
      if (config.logRetries && attempt > 0) {
        console.log(`[ApiRetry] Încercarea ${attempt}/${config.maxRetries} pentru ${options.method || 'GET'} ${url}`);
      }
      
      const response = await fetch(url, fetchOptions);
      clearTimeout(timeoutId);
      
      // Verificăm dacă răspunsul necesită reîncercare
      if (
        !response.ok && 
        config.retryStatusCodes.includes(response.status) && 
        config.retryMethods.includes(options.method || 'GET') &&
        attempt < config.maxRetries
      ) {
        attempt++;
        lastError = new Error(`Răspuns cu status ${response.status}`);
        
        // Calculăm delay-ul pentru următoarea încercare (backoff exponențial cu jitter)
        delay = Math.min(delay * config.backoffFactor, config.maxDelay);
        delay = delay * (0.8 + Math.random() * 0.4); // Adăugăm jitter (±20%)
        
        if (config.logRetries) {
          console.log(`[ApiRetry] Răspuns cu status ${response.status}, se reîncearcă în ${Math.round(delay)}ms`);
        }
        
        await new Promise(resolve => setTimeout(resolve, delay));
        continue;
      }
      
      // Procesăm răspunsul
      let responseData;
      const contentType = response.headers.get('content-type');
      
      if (contentType && contentType.includes('application/json')) {
        responseData = await response.json();
      } else {
        responseData = await response.text();
      }
      
      // Actualizăm circuit breaker-ul în caz de succes
      updateCircuitBreakerOnSuccess();
      
      // Adăugăm în cache dacă este activat
      if (config.cacheSuccessfulResponses && response.ok) {
        const cacheKey = `api-${options.method || 'GET'}-${url}-${JSON.stringify(options.body || {})}`;
        memoryCache.set(cacheKey, responseData, config.cacheTTL);
      }
      
      return responseData;
    } catch (error) {
      clearTimeout(timeoutId);
      lastError = error;
      
      // Verificăm dacă eroarea este de timeout
      const isTimeout = error.name === 'AbortError';
      
      // Verificăm dacă trebuie să reîncercăm
      if (attempt < config.maxRetries && (isTimeout || error.code === 'ECONNRESET' || error.code === 'ETIMEDOUT')) {
        attempt++;
        
        // Calculăm delay-ul pentru următoarea încercare
        delay = Math.min(delay * config.backoffFactor, config.maxDelay);
        delay = delay * (0.8 + Math.random() * 0.4); // Adăugăm jitter (±20%)
        
        if (config.logRetries) {
          console.log(`[ApiRetry] Eroare: ${error.message}, se reîncearcă în ${Math.round(delay)}ms`);
        }
        
        await new Promise(resolve => setTimeout(resolve, delay));
        continue;
      }
      
      // Actualizăm circuit breaker-ul în caz de eșec
      updateCircuitBreakerOnFailure();
      
      // Aruncăm eroarea finală
      throw new Error(`Apel API eșuat după ${attempt} încercări: ${error.message}`);
    }
  }
  
  // Dacă ajungem aici, toate încercările au eșuat
  throw lastError;
}

/**
 * Resetează toate circuit breaker-urile
 */
function resetAllCircuitBreakers() {
  for (const [key, breaker] of circuitBreakers.entries()) {
    breaker.state = 'closed';
    breaker.failures = 0;
    breaker.lastFailure = 0;
    console.log(`[ApiRetry] Circuit breaker pentru ${key} a fost resetat manual`);
  }
}

/**
 * Obține starea tuturor circuit breaker-urilor
 * @returns {Object} - Starea circuit breaker-urilor
 */
function getCircuitBreakersStatus() {
  const status = {};
  for (const [key, breaker] of circuitBreakers.entries()) {
    status[key] = {
      state: breaker.state,
      failures: breaker.failures,
      lastFailure: breaker.lastFailure,
      timeSinceLastFailure: breaker.lastFailure ? Date.now() - breaker.lastFailure : null
    };
  }
  return status;
}

// Exportă funcțiile
export default {
  fetchWithRetry,
  resetAllCircuitBreakers,
  getCircuitBreakersStatus
};