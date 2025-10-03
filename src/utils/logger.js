// src/utils/logger.js - Sistem avansat de logging
// Oferă funcționalități de logging structurat, rotație de fișiere și integrare cu Sentry

import * as Sentry from '@sentry/node';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

// Obținem directorul curent
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Configurare implicită
const DEFAULT_CONFIG = {
  logLevel: process.env.NODE_ENV === 'production' ? 'info' : 'debug',
  logToConsole: true,
  logToFile: process.env.NODE_ENV === 'production',
  logDir: path.join(__dirname, '../../logs'),
  maxLogSize: 10 * 1024 * 1024, // 10 MB
  maxLogFiles: 10,
  sentryEnabled: process.env.SENTRY_DSN ? true : false,
  sentryLevel: 'error',
  includeTimestamp: true,
  includeRequestId: true,
  maskSensitiveData: true,
  sensitiveFields: ['password', 'token', 'apiKey', 'secret', 'credit_card']
};

// Niveluri de logging
const LOG_LEVELS = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3,
  fatal: 4
};

// Culori pentru console
const COLORS = {
  reset: '\x1b[0m',
  debug: '\x1b[36m', // Cyan
  info: '\x1b[32m',  // Verde
  warn: '\x1b[33m',  // Galben
  error: '\x1b[31m', // Roșu
  fatal: '\x1b[35m'  // Magenta
};

// Stocăm configurarea curentă
let config = { ...DEFAULT_CONFIG };
let currentLogFile = null;
let currentLogSize = 0;

/**
 * Inițializează sistemul de logging
 * @param {Object} options - Opțiuni de configurare
 */
function init(options = {}) {
  config = { ...DEFAULT_CONFIG, ...options };
  
  // Creăm directorul de log-uri dacă nu există
  if (config.logToFile) {
    if (!fs.existsSync(config.logDir)) {
      fs.mkdirSync(config.logDir, { recursive: true });
    }
    
    // Inițializăm fișierul de log curent
    rotateLogFileIfNeeded();
  }
  
  // Inițializăm Sentry dacă este activat
  if (config.sentryEnabled && process.env.SENTRY_DSN) {
    Sentry.init({
      dsn: process.env.SENTRY_DSN,
      environment: process.env.NODE_ENV || 'development',
      tracesSampleRate: 1.0
    });
    
    // Înregistrăm inițializarea
    debug('Sentry inițializat cu succes');
  }
  
  // Înregistrăm inițializarea
  info('Sistem de logging inițializat cu succes');
}

/**
 * Rotește fișierul de log dacă este necesar
 */
function rotateLogFileIfNeeded() {
  if (!config.logToFile) return;
  
  // Verificăm dacă avem un fișier de log curent
  if (currentLogFile) {
    // Verificăm dimensiunea fișierului
    try {
      const stats = fs.statSync(currentLogFile);
      currentLogSize = stats.size;
      
      // Rotim fișierul dacă a depășit dimensiunea maximă
      if (currentLogSize >= config.maxLogSize) {
        rotateLogFile();
      }
    } catch (error) {
      console.error(`Eroare la verificarea dimensiunii fișierului de log: ${error.message}`);
      // Creăm un nou fișier de log
      createNewLogFile();
    }
  } else {
    // Creăm un nou fișier de log
    createNewLogFile();
  }
}

/**
 * Creează un nou fișier de log
 */
function createNewLogFile() {
  if (!config.logToFile) return;
  
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const fileName = `app-${timestamp}.log`;
  currentLogFile = path.join(config.logDir, fileName);
  currentLogSize = 0;
  
  // Scriem header-ul în fișier
  const header = `=== Log început la ${new Date().toISOString()} ===\n`;
  fs.writeFileSync(currentLogFile, header);
  currentLogSize = header.length;
  
  // Curățăm fișierele vechi
  cleanOldLogFiles();
}

/**
 * Rotește fișierul de log curent
 */
function rotateLogFile() {
  if (!config.logToFile || !currentLogFile) return;
  
  // Închidem fișierul curent
  const footer = `=== Log închis la ${new Date().toISOString()} ===\n`;
  fs.appendFileSync(currentLogFile, footer);
  
  // Creăm un nou fișier
  createNewLogFile();
}

/**
 * Curăță fișierele de log vechi
 */
function cleanOldLogFiles() {
  if (!config.logToFile) return;
  
  try {
    // Obținem toate fișierele de log
    const files = fs.readdirSync(config.logDir)
      .filter(file => file.startsWith('app-') && file.endsWith('.log'))
      .map(file => ({
        name: file,
        path: path.join(config.logDir, file),
        time: fs.statSync(path.join(config.logDir, file)).mtime.getTime()
      }))
      .sort((a, b) => b.time - a.time); // Sortăm descrescător după timp
    
    // Ștergem fișierele vechi
    if (files.length > config.maxLogFiles) {
      for (let i = config.maxLogFiles; i < files.length; i++) {
        fs.unlinkSync(files[i].path);
      }
    }
  } catch (error) {
    console.error(`Eroare la curățarea fișierelor de log vechi: ${error.message}`);
  }
}

/**
 * Formatează un mesaj de log
 * @param {string} level - Nivelul de log
 * @param {string} message - Mesajul de log
 * @param {Object} meta - Metadate adiționale
 * @returns {string} - Mesajul formatat
 */
function formatLogMessage(level, message, meta = {}) {
  const parts = [];
  
  // Adăugăm timestamp
  if (config.includeTimestamp) {
    parts.push(`[${new Date().toISOString()}]`);
  }
  
  // Adăugăm nivelul
  parts.push(`[${level.toUpperCase()}]`);
  
  // Adăugăm request ID
  if (config.includeRequestId && meta.requestId) {
    parts.push(`[${meta.requestId}]`);
  }
  
  // Adăugăm mesajul
  parts.push(message);
  
  // Adăugăm metadatele
  if (Object.keys(meta).length > 0 && meta.requestId !== undefined) {
    // Eliminăm requestId din meta pentru a evita duplicarea
    const { requestId, ...restMeta } = meta;
    
    if (Object.keys(restMeta).length > 0) {
      // Mascăm datele sensibile
      const metaToLog = config.maskSensitiveData ? maskSensitiveData(restMeta) : restMeta;
      parts.push(JSON.stringify(metaToLog));
    }
  } else if (Object.keys(meta).length > 0) {
    // Mascăm datele sensibile
    const metaToLog = config.maskSensitiveData ? maskSensitiveData(meta) : meta;
    parts.push(JSON.stringify(metaToLog));
  }
  
  return parts.join(' ');
}

/**
 * Mascăm datele sensibile
 * @param {Object} data - Datele de mascat
 * @returns {Object} - Datele mascate
 */
function maskSensitiveData(data) {
  if (!data || typeof data !== 'object') return data;
  
  const masked = Array.isArray(data) ? [...data] : { ...data };
  
  for (const key in masked) {
    if (config.sensitiveFields.includes(key.toLowerCase())) {
      masked[key] = '********';
    } else if (typeof masked[key] === 'object' && masked[key] !== null) {
      masked[key] = maskSensitiveData(masked[key]);
    }
  }
  
  return masked;
}

/**
 * Scrie un mesaj de log
 * @param {string} level - Nivelul de log
 * @param {string} message - Mesajul de log
 * @param {Object} meta - Metadate adiționale
 */
function log(level, message, meta = {}) {
  // Verificăm dacă nivelul este suficient
  if (LOG_LEVELS[level] < LOG_LEVELS[config.logLevel]) {
    return;
  }
  
  // Formatăm mesajul
  const formattedMessage = formatLogMessage(level, message, meta);
  
  // Scriem în consolă
  if (config.logToConsole) {
    const color = COLORS[level] || COLORS.reset;
    console.log(`${color}${formattedMessage}${COLORS.reset}`);
  }
  
  // Scriem în fișier
  if (config.logToFile) {
    rotateLogFileIfNeeded();
    
    if (currentLogFile) {
      try {
        const logLine = `${formattedMessage}\n`;
        fs.appendFileSync(currentLogFile, logLine);
        currentLogSize += logLine.length;
      } catch (error) {
        console.error(`Eroare la scrierea în fișierul de log: ${error.message}`);
      }
    }
  }
  
  // Trimitem la Sentry
  if (config.sentryEnabled && LOG_LEVELS[level] >= LOG_LEVELS[config.sentryLevel]) {
    try {
      Sentry.captureMessage(message, {
        level,
        extra: meta
      });
    } catch (error) {
      console.error(`Eroare la trimiterea log-ului către Sentry: ${error.message}`);
    }
  }
}

/**
 * Înregistrează un mesaj de debug
 * @param {string} message - Mesajul de log
 * @param {Object} meta - Metadate adiționale
 */
function debug(message, meta = {}) {
  log('debug', message, meta);
}

/**
 * Înregistrează un mesaj informativ
 * @param {string} message - Mesajul de log
 * @param {Object} meta - Metadate adiționale
 */
function info(message, meta = {}) {
  log('info', message, meta);
}

/**
 * Înregistrează un avertisment
 * @param {string} message - Mesajul de log
 * @param {Object} meta - Metadate adiționale
 */
function warn(message, meta = {}) {
  log('warn', message, meta);
}

/**
 * Înregistrează o eroare
 * @param {string} message - Mesajul de log
 * @param {Error|Object} error - Eroarea sau metadate adiționale
 * @param {Object} meta - Metadate adiționale
 */
function error(message, error = {}, meta = {}) {
  // Procesăm eroarea
  let errorMeta = meta;
  
  if (error instanceof Error) {
    errorMeta = {
      ...meta,
      error: {
        message: error.message,
        stack: error.stack,
        name: error.name
      }
    };
    
    // Trimitem eroarea la Sentry
    if (config.sentryEnabled) {
      try {
        Sentry.captureException(error, {
          extra: { ...meta, message }
        });
      } catch (sentryError) {
        console.error(`Eroare la trimiterea excepției către Sentry: ${sentryError.message}`);
      }
    }
  } else if (typeof error === 'object') {
    errorMeta = { ...error, ...meta };
  }
  
  log('error', message, errorMeta);
}

/**
 * Înregistrează o eroare fatală
 * @param {string} message - Mesajul de log
 * @param {Error|Object} error - Eroarea sau metadate adiționale
 * @param {Object} meta - Metadate adiționale
 */
function fatal(message, error = {}, meta = {}) {
  // Procesăm eroarea
  let errorMeta = meta;
  
  if (error instanceof Error) {
    errorMeta = {
      ...meta,
      error: {
        message: error.message,
        stack: error.stack,
        name: error.name
      }
    };
    
    // Trimitem eroarea la Sentry
    if (config.sentryEnabled) {
      try {
        Sentry.captureException(error, {
          level: 'fatal',
          extra: { ...meta, message }
        });
      } catch (sentryError) {
        console.error(`Eroare la trimiterea excepției către Sentry: ${sentryError.message}`);
      }
    }
  } else if (typeof error === 'object') {
    errorMeta = { ...error, ...meta };
  }
  
  log('fatal', message, errorMeta);
}

/**
 * Middleware Fastify pentru logging
 * @param {FastifyInstance} fastify - Instanța Fastify
 */
function fastifyPlugin(fastify, options, done) {
  // Inițializăm logger-ul
  init(options);
  
  // Adăugăm middleware pentru logging
  fastify.addHook('onRequest', (request, reply, done) => {
    // Generăm un ID unic pentru request
    const requestId = `req-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    request.requestId = requestId;
    
    // Înregistrăm începutul request-ului
    debug(`${request.method} ${request.url} început`, {
      requestId,
      method: request.method,
      url: request.url,
      ip: request.ip,
      headers: config.maskSensitiveData ? maskSensitiveData(request.headers) : request.headers
    });
    
    // Măsurăm timpul de procesare
    request.startTime = process.hrtime();
    
    done();
  });
  
  // Înregistrăm sfârșitul request-ului
  fastify.addHook('onResponse', (request, reply, done) => {
    // Calculăm timpul de procesare
    const hrtime = process.hrtime(request.startTime);
    const responseTime = hrtime[0] * 1000 + hrtime[1] / 1000000;
    
    // Înregistrăm sfârșitul request-ului
    info(`${request.method} ${request.url} terminat în ${responseTime.toFixed(2)}ms cu status ${reply.statusCode}`, {
      requestId: request.requestId,
      method: request.method,
      url: request.url,
      statusCode: reply.statusCode,
      responseTime
    });
    
    done();
  });
  
  // Înregistrăm erorile
  fastify.addHook('onError', (request, reply, error, done) => {
    error(`Eroare la procesarea ${request.method} ${request.url}`, error, {
      requestId: request.requestId,
      method: request.method,
      url: request.url,
      statusCode: reply.statusCode
    });
    
    done();
  });
  
  // Decorăm instanța Fastify cu logger-ul
  fastify.decorate('logger', {
    debug: (message, meta = {}) => debug(message, { ...meta, requestId: fastify.requestId }),
    info: (message, meta = {}) => info(message, { ...meta, requestId: fastify.requestId }),
    warn: (message, meta = {}) => warn(message, { ...meta, requestId: fastify.requestId }),
    error: (message, error = {}, meta = {}) => error(message, error, { ...meta, requestId: fastify.requestId }),
    fatal: (message, error = {}, meta = {}) => fatal(message, error, { ...meta, requestId: fastify.requestId })
  });
  
  done();
}

// Exportă funcțiile
export default {
  init,
  debug,
  info,
  warn,
  error,
  fatal,
  fastifyPlugin
};