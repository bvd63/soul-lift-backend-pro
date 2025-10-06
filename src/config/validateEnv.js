// src/config/validateEnv.js — Validare ENV obligatorii și recomandate
export function validateEnv({ isProd = false } = {}) {
  const env = process.env;
  const errors = [];
  const warnings = [];
  // Required keys (production-critical)
  if (!env.JWT_SECRET) errors.push('JWT_SECRET missing');
  // Payment
  const stripeSecret = env.STRIPE_SECRET_KEY || env.STRIPE_SECRET;
  if (!stripeSecret) warnings.push('STRIPE_SECRET_KEY missing (payments disabled)');
  if (!env.STRIPE_WEBHOOK_SECRET) warnings.push('STRIPE_WEBHOOK_SECRET missing (webhooks will not be verified)');

  // AI keys (recommended but not strictly blocking in dev)
  if (!env.OPENAI_API_KEY) warnings.push('OPENAI_API_KEY missing (AI features disabled)');
  if (!env.DEEPL_API_KEY) warnings.push('DEEPL_API_KEY missing (DeepL fallback disabled)');

  // Redis: accept REDIS_URL or UPSTASH_REDIS_REST_URL or host/port/password
  const hasRedisUrl = !!env.REDIS_URL || !!env.UPSTASH_REDIS_REST_URL;
  const hasRedisTriplet = !!env.REDIS_HOST && !!env.REDIS_PORT && !!env.REDIS_PASSWORD;
  if (!hasRedisUrl && !hasRedisTriplet) warnings.push('Redis config missing: REDIS_URL or REDIS_HOST/REDIS_PORT/REDIS_PASSWORD (cache disabled)');

  // Optional but helpful
  if (!env.APP_ENV) warnings.push('APP_ENV not set');
  if (!env.LOG_LEVEL) warnings.push('LOG_LEVEL not set');
  if (!env.ALLOWED_ORIGINS && !env.CORS_ORIGINS) warnings.push('ALLOWED_ORIGINS or CORS_ORIGINS not set');
  if (!env.BUILD_COMMIT) warnings.push('BUILD_COMMIT not set');
  if (!env.BUILD_TIME) warnings.push('BUILD_TIME not set');

  // In production, some warnings should be treated as errors
  if (isProd) {
    // required in prod
    if (!env.STRIPE_WEBHOOK_SECRET) errors.push('STRIPE_WEBHOOK_SECRET missing (required in production)');
    if (!hasRedisUrl && !hasRedisTriplet) errors.push('Redis config missing: REDIS_URL or REDIS_HOST/REDIS_PORT/REDIS_PASSWORD');
    if (!env.OPENAI_API_KEY && !env.DEEPL_API_KEY) warnings.push('No AI provider configured (OPENAI_API_KEY or DEEPL_API_KEY)');
  }

  const ok = errors.length === 0; // in production must have no errors; in dev caller may override isProd flag
  return { ok, errors, warnings };
}

export default { validateEnv };
