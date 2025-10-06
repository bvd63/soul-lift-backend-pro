// src/config/validateEnv.js — Validare ENV obligatorii și recomandate
export function validateEnv({ isProd = false } = {}) {
  const env = process.env;
  const errors = [];
  const warnings = [];

  // Obligatorii
  if (!env.OPENAI_API_KEY) errors.push('OPENAI_API_KEY missing');
  if (!env.DEEPL_API_KEY) errors.push('DEEPL_API_KEY missing');
  if (!env.JWT_SECRET) errors.push('JWT_SECRET missing');

  // Stripe (acceptă STRIPE_SECRET_KEY sau STRIPE_SECRET)
  const stripeSecret = env.STRIPE_SECRET_KEY || env.STRIPE_SECRET;
  if (!stripeSecret) errors.push('STRIPE_SECRET_KEY missing');
  if (!env.STRIPE_WEBHOOK_SECRET) warnings.push('STRIPE_WEBHOOK_SECRET missing');

  // Redis: accepți fie REDIS_URL, fie trio host/port/password
  const hasRedisUrl = !!env.REDIS_URL || !!env.UPSTASH_REDIS_REST_URL;
  const hasRedisTriplet = !!env.REDIS_HOST && !!env.REDIS_PORT && !!env.REDIS_PASSWORD;
  if (!hasRedisUrl && !hasRedisTriplet) errors.push('Redis config missing: REDIS_URL or REDIS_HOST/REDIS_PORT/REDIS_PASSWORD');

  // Recomandate
  if (!env.APP_ENV) warnings.push('APP_ENV not set');
  if (!env.LOG_LEVEL) warnings.push('LOG_LEVEL not set');
  if (!env.ALLOWED_ORIGINS && !env.CORS_ORIGINS) warnings.push('ALLOWED_ORIGINS or CORS_ORIGINS not set');
  if (!env.BUILD_COMMIT) warnings.push('BUILD_COMMIT not set');
  if (!env.BUILD_TIME) warnings.push('BUILD_TIME not set');

  const ok = errors.length === 0 || !isProd; // în dev/test nu blocăm pornirea
  return { ok, errors, warnings };
}

export default { validateEnv };
