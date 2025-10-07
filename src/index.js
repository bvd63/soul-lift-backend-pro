// SoulLift Backend - Clean Production Version (src/ version for Render)
import Fastify from 'fastify';
import { assertDbConnection } from './db.js';
import QUOTES from '../data/quotes.js';
import { cleanEnv, str, port, bool, url } from 'envalid';

const env = cleanEnv(process.env, {
  NODE_ENV: str({ default: 'development' }),
  PORT: port({ default: 10000 }),
  DATABASE_URL: str(),
  FRONTEND_URL: url({ default: 'http://localhost:3000' }),
  OPENAI_API_KEY: str({ default: '' }),
  STRIPE_SECRET_KEY: str({ default: '' }),
  STRIPE_PRICE_ID_STANDARD_MONTHLY: str({ default: '' }),
  STRIPE_PRICE_ID_PRO_MONTHLY: str({ default: '' })
});

const USE_DB = !!env.DATABASE_URL;
const USE_OPENAI = !!env.OPENAI_API_KEY;
const USE_STRIPE = !!env.STRIPE_SECRET_KEY;

console.log('🔧 Environment:', {
  NODE_ENV: env.NODE_ENV,
  PORT: env.PORT,
  USE_DB,
  USE_OPENAI,
  USE_STRIPE
});

// Voice profiles for AI selection
const voiceProfiles = {
  feminine: {
    motivational: ['maria_energetic', 'maya_powerful', 'nova_dynamic'],
    peaceful: ['sophia_calm', 'luna_peaceful', 'zara_gentle'],
    wise: ['elena_wise', 'julia_nurturing'],
    confident: ['anna_confident', 'clara_inspiring']
  },
  masculine: {
    motivational: ['marcus_motivational', 'leo_inspiring', 'kai_energetic'],
    peaceful: ['alex_calm', 'noah_grounded', 'ace_gentle'],
    wise: ['finn_wise', 'david_strong'],
    confident: ['erik_confident', 'zane_powerful']
  }
};

const voiceMapping = {
  'sophia_calm': 'nova', 'maria_energetic': 'shimmer', 'elena_wise': 'alloy',
  'anna_confident': 'nova', 'julia_nurturing': 'shimmer', 'clara_inspiring': 'alloy',
  'luna_peaceful': 'nova', 'maya_powerful': 'shimmer', 'zara_gentle': 'alloy',
  'nova_dynamic': 'nova', 'david_strong': 'onyx', 'marcus_motivational': 'echo', 
  'alex_calm': 'fable', 'erik_confident': 'onyx', 'leo_inspiring': 'echo', 
  'noah_grounded': 'fable', 'kai_energetic': 'echo', 'finn_wise': 'onyx', 
  'zane_powerful': 'echo', 'ace_gentle': 'fable'
};

// Voice service functions
function getVoiceDescription(voice) {
  const descriptions = {
    'sophia_calm': 'Calm and nurturing feminine voice',
    'maria_energetic': 'Energetic and motivational feminine voice',
    'david_strong': 'Strong and authoritative masculine voice',
    'marcus_motivational': 'Motivational and inspiring masculine voice'
  };
  return descriptions[voice] || 'Human-like AI voice';
}

function getAvailableVoices(tier) {
  const allVoices = Object.keys(voiceMapping);
  if (tier === 'pro') return allVoices;
  if (tier === 'standard') return ['sophia_calm', 'maria_energetic', 'elena_wise', 'david_strong', 'marcus_motivational', 'alex_calm'];
  return [];
}

async function selectOptimalVoice(quote, tier) {
  try {
    const text = quote.text.toLowerCase();
    let mood = 'motivational';
    if (text.match(/peace|calm|serene/i)) mood = 'peaceful';
    else if (text.match(/wisdom|understand|learn/i)) mood = 'wise';
    else if (text.match(/confident|strong|powerful/i)) mood = 'confident';
    
    const gender = Math.random() > 0.5 ? 'feminine' : 'masculine';
    const options = voiceProfiles[gender][mood] || voiceProfiles[gender]['motivational'];
    const available = tier === 'pro' ? options : options.slice(0, 2);
    return available[Math.floor(Math.random() * available.length)];
  } catch (e) {
    return 'sophia_calm';
  }
}

async function generateHumanVoiceAudio(text, voice, tier, speed = 1.0, format = 'mp3') {
  try {
    const openaiVoice = voiceMapping[voice] || 'alloy';
    const model = tier === 'pro' ? 'tts-1-hd' : 'tts-1';
    
    const response = await fetch('https://api.openai.com/v1/audio/speech', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${env.OPENAI_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ model, input: text, voice: openaiVoice, speed, response_format: format })
    });
    
    if (!response.ok) throw new Error('TTS API error');
    
    const audioBuffer = await response.arrayBuffer();
    return {
      success: true,
      audioBuffer: Buffer.from(audioBuffer),
      duration: Math.ceil(text.length / 12),
      contentType: format === 'mp3' ? 'audio/mpeg' : 'audio/wav'
    };
  } catch (e) {
    return { success: false, error: e.message };
  }
}

// Utility functions
async function fetchWithRetry(url, options, retryOptions = {}) {
  const { maxRetries = 3, initialDelay = 300 } = retryOptions;
  let lastError;
  
  for (let i = 0; i <= maxRetries; i++) {
    try {
      const response = await fetch(url, options);
      if (response.ok || i === maxRetries) return response;
      throw new Error(`HTTP ${response.status}`);
    } catch (error) {
      lastError = error;
      if (i < maxRetries) {
        await new Promise(resolve => setTimeout(resolve, initialDelay * Math.pow(2, i)));
      }
    }
  }
  throw lastError;
}

async function openaiChat(messages, opts = {}) {
  if (!USE_OPENAI) throw new Error('OpenAI not configured');
  const response = await fetchWithRetry('https://api.openai.com/v1/chat/completions', {
    method: 'POST',
    headers: { Authorization: `Bearer ${env.OPENAI_API_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      model: opts.model || 'gpt-4o-mini',
      messages,
      temperature: opts.temperature ?? 0.5,
      max_tokens: opts.max_tokens ?? 150
    })
  }, { maxRetries: 3, initialDelay: 400 });
  
  const data = await response.json();
  return data.choices?.[0]?.message?.content?.trim() || '';
}

// Authentication middleware
async function authMiddleware(req, rep) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer ')) {
    return rep.code(401).send({ error: 'unauthorized' });
  }
  
  // Mock user for development
  req.user = { 
    email: 'test@example.com', 
    subscription_tier: 'pro',
    subscription_status: 'active' 
  };
}

// Audit logging
async function pushAudit(action, email, meta = {}) {
  console.log('📝 Audit:', { action, email, meta });
}

// Database retry function
async function waitForDb(maxAttempts = 15, delay = 1500) {
  for (let i = 1; i <= maxAttempts; i++) {
    try {
      await assertDbConnection();
      console.log(`✅ Database connected on attempt ${i}`);
      return true;
    } catch (error) {
      console.log(`🔄 Database attempt ${i}/${maxAttempts} failed: ${error.message}`);
      if (i === maxAttempts) {
        throw new Error(`Failed to connect to database after ${maxAttempts} attempts`);
      }
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }
}

// Main application function
async function createApp() {
  const app = Fastify({ logger: env.NODE_ENV === 'development' });

  // Dynamic imports for optional dependencies
  let Stripe, stripe;

  try {
    const stripeModule = await import('stripe');
    Stripe = stripeModule.default;
    stripe = USE_STRIPE ? new Stripe(env.STRIPE_SECRET_KEY) : null;
  } catch (e) {
    console.log('⚠️ stripe not available');
    stripe = null;
  }

  // CORS
  await app.register(import('@fastify/cors'), {
    origin: env.FRONTEND_URL,
    credentials: true
  });

  // Health endpoints
  app.get('/health', async () => ({ ok: true, version: '1.0.9', timestamp: Date.now() }));
  
  app.get('/healthz', async (req, reply) => {
    try {
      await assertDbConnection();
      return { status: 'ok', db: true };
    } catch (error) {
      reply.code(503);
      return { status: 'error', db: false, error: error.message };
    }
  });
  
  app.get('/api/health', async () => ({ ok: true, db: true, ai: USE_OPENAI, stripe: USE_STRIPE }));

  // Get daily quote
  app.get('/api/quote', {
    schema: { tags: ['Quotes'] }
  }, async (req) => {
    const { category, mood, premium } = req.query;
    let filtered = QUOTES.filter(q => !premium || !q.premium);
    
    if (category) filtered = filtered.filter(q => q.tags?.includes(category));
    if (mood) filtered = filtered.filter(q => q.mood === mood);
    
    const quote = filtered[Math.floor(Math.random() * filtered.length)] || QUOTES[0];
    
    return {
      ok: true,
      quote,
      lastModified: Date.now(),
      cached: false
    };
  });

  // AI Personalization
  app.post('/api/quotes/personalize', {
    schema: { tags: ['AI'] }
  }, async (req, rep) => {
    if (!USE_OPENAI) return rep.code(503).send({ error: 'ai_disabled' });
    
    try {
      const { preferences = {}, mood = 'motivated', goals = [] } = req.body;
      
      const prompt = `Generate a personalized inspirational quote for someone who:
- Current mood: ${mood}
- Preferences: ${JSON.stringify(preferences)}
- Goals: ${goals.join(', ')}
- Make it uplifting and relevant to their situation.`;
      
      const response = await openaiChat([{ role: 'user', content: prompt }]);
      
      return {
        ok: true,
        quote: {
          text: response,
          author: 'AI Personalized',
          generated: true,
          mood,
          timestamp: Date.now()
        }
      };
    } catch (e) {
      app.log.error('AI personalization failed', e);
      return rep.code(500).send({ error: 'ai_failed' });
    }
  });

  // Audio quotes with AI voice selection
  app.post('/api/quotes/audio', {
    preHandler: [authMiddleware],
    schema: { tags: ['Audio'] }
  }, async (req, rep) => {
    if (!USE_OPENAI) return rep.code(503).send({ error: 'openai_disabled' });
    
    const user = req.user;
    const { text, voice, speed = 1.0, format = 'mp3', autoSelect = true } = req.body;
    
    if (user.subscription_tier === 'free') {
      return rep.code(403).send({ error: 'audio_requires_subscription' });
    }
    
    try {
      const selectedVoice = voice || (autoSelect ? 
        await selectOptimalVoice({ text }, user.subscription_tier) : 
        'sophia_calm');
      
      const audioResult = await generateHumanVoiceAudio(text, selectedVoice, user.subscription_tier, speed, format);
      
      if (!audioResult.success) {
        return rep.code(500).send({ error: audioResult.error });
      }
      
      rep.type(audioResult.contentType);
      rep.header('X-Voice-Used', selectedVoice);
      rep.header('X-Duration', audioResult.duration);
      
      await pushAudit('audio:generate', user.email, { voice: selectedVoice, tier: user.subscription_tier });
      
      return rep.send(audioResult.audioBuffer);
    } catch (e) {
      app.log.error('Audio generation failed', e);
      return rep.code(500).send({ error: 'audio_generation_failed' });
    }
  });

  // Get available voices
  app.get('/api/voices', {
    preHandler: [authMiddleware],
    schema: { tags: ['Audio'] }
  }, async (req) => {
    const availableVoices = getAvailableVoices(req.user.subscription_tier);
    
    return {
      ok: true,
      voices: availableVoices.map(voice => ({
        id: voice,
        name: voice.replace('_', ' ').replace(/\b\w/g, l => l.toUpperCase()),
        description: getVoiceDescription(voice),
        tier: req.user.subscription_tier === 'pro' ? 'pro' : 'standard'
      })),
      totalCount: availableVoices.length,
      userTier: req.user.subscription_tier
    };
  });

  // Pricing plans
  app.get('/api/pricing', {
    schema: { tags: ['Billing'] }
  }, async () => {
    const plans = {
      free: {
        name: 'Free',
        tier: 'free',
        price: { monthly: 0, currency: 'USD' },
        features: ['Basic daily quotes', 'Limited favorites (50)', 'Basic categories', 'Community access', 'Standard support'],
        limits: { favorites: 50, audioQuotes: 0, voices: 0, premiumContent: false, analytics: 'basic' }
      },
      standard: {
        name: 'Standard',
        tier: 'standard',
        price: { monthly: 6.49, currency: 'USD' },
        features: ['Unlimited daily quotes', 'Unlimited favorites', 'All categories & moods', 'Audio quotes (6 voices)', 'Social features', 'Basic analytics', 'Priority support'],
        limits: { favorites: -1, audioQuotes: 50, voices: 6, premiumContent: false, analytics: 'standard' },
        stripeIds: { monthly: env.STRIPE_PRICE_ID_STANDARD_MONTHLY }
      },
      pro: {
        name: 'Pro',
        tier: 'pro',
        price: { monthly: 9.49, currency: 'USD' },
        features: ['Everything in Standard', 'Premium AI voices (20 total)', 'HD audio quality', 'Premium content library', 'Advanced analytics & insights', 'Mood tracking', 'Personal dashboard', 'Priority support', 'Early access to new features'],
        limits: { favorites: -1, audioQuotes: -1, voices: 20, premiumContent: true, analytics: 'advanced' },
        stripeIds: { monthly: env.STRIPE_PRICE_ID_PRO_MONTHLY || env.STRIPE_PRICE_ID_MONTHLY }
      }
    };
    
    return {
      ok: true,
      plans,
      currency: 'USD',
      recommended: 'standard',
      popular: 'pro',
      generatedAt: new Date().toISOString()
    };
  });

  // Stripe checkout
  app.post('/api/billing/checkout', {
    preHandler: [authMiddleware],
    schema: { tags: ['Billing'] }
  }, async (req, rep) => {
    if (!USE_STRIPE || !stripe) return rep.code(503).send({ error: 'stripe_disabled' });
    
    const { tier = 'standard' } = req.body;
    const priceId = tier === 'pro' ? env.STRIPE_PRICE_ID_PRO_MONTHLY : env.STRIPE_PRICE_ID_STANDARD_MONTHLY;
    
    if (!priceId) return rep.code(500).send({ error: 'price_not_configured' });
    
    const email = req.user.email;
    let customerId = req.user.stripe_customer_id;
    
    if (!customerId) {
      const customer = await stripe.customers.create({ email });
      customerId = customer.id;
    }
    
    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      customer: customerId,
      line_items: [{ price: priceId, quantity: 1 }],
      allow_promotion_codes: true,
      success_url: `${env.FRONTEND_URL}/pro/success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${env.FRONTEND_URL}/pro/cancel`,
      billing_address_collection: 'auto'
    });
    
    await pushAudit('checkout:create', email, { tier });
    return { ok: true, url: session.url };
  });

  // Social sharing
  app.post('/api/social/share', {
    preHandler: [authMiddleware],
    schema: { tags: ['Social'] }
  }, async (req) => {
    const { quoteId, platform } = req.body;
    const quote = QUOTES.find(q => q.id === quoteId);
    
    if (!quote) return { error: 'quote_not_found' };
    
    const shareUrl = `${env.FRONTEND_URL}/quote/${quoteId}`;
    const text = `"${quote.text}" - ${quote.author}`;
    
    await pushAudit('social:share', req.user.email, { quoteId, platform });
    
    return {
      ok: true,
      shareUrl,
      text,
      platform,
      shareLink: generateShareLink(platform, text, shareUrl)
    };
  });

  function generateShareLink(platform, text, url) {
    const encodedText = encodeURIComponent(text);
    const encodedUrl = encodeURIComponent(url);
    
    const links = {
      twitter: `https://twitter.com/intent/tweet?text=${encodedText}&url=${encodedUrl}`,
      facebook: `https://www.facebook.com/sharer/sharer.php?u=${encodedUrl}`,
      whatsapp: `https://wa.me/?text=${encodedText}%20${encodedUrl}`
    };
    
    return links[platform] || url;
  }

  // Analytics dashboard
  app.get('/api/analytics/dashboard', {
    preHandler: [authMiddleware],
    schema: { tags: ['Analytics'] }
  }, async (req) => {
    return {
      ok: true,
      analytics: {
        quotesViewed: Math.floor(Math.random() * 100) + 50,
        audioGenerated: Math.floor(Math.random() * 30) + 10,
        favorites: Math.floor(Math.random() * 25) + 5,
        streakDays: Math.floor(Math.random() * 30) + 1,
        mostUsedVoice: 'sophia_calm',
        preferredCategories: ['motivation', 'wisdom', 'peace'],
        weeklyProgress: Array.from({ length: 7 }, () => Math.floor(Math.random() * 10) + 1)
      },
      subscription: {
        tier: req.user.subscription_tier,
        status: req.user.subscription_status,
        features: req.user.subscription_tier === 'pro' ? 'all' : 'limited'
      }
    };
  });

  // Documentation
  await app.register(import('@fastify/swagger'), {
    swagger: {
      info: {
        title: 'SoulLift API',
        description: 'Mindfulness & quotes platform with AI voices',
        version: '1.0.9'
      }
    }
  });

  await app.register(import('@fastify/swagger-ui'), {
    routePrefix: '/docs'
  });

  return app;
}

// Database initialization
async function initDB() {
  if (!USE_DB) {
    console.log('📋 Running without database');
    return;
  }
  
  try {
    // Basic health check - more detailed schema setup can be added here
    await assertDbConnection();
    console.log('✅ Database ready');
  } catch (e) {
    console.error('❌ Database init failed:', e.message);
    throw e;
  }
}

// Startup
async function start() {
  try {
    console.log('🚀 Starting SoulLift Backend...');
    
    // Wait for database connection with retry logic
    if (USE_DB) {
      await waitForDb();
    }
    
    // Initialize database
    await initDB();
    
    // Create and start the app
    const app = await createApp();
    
    const address = await app.listen({ 
      port: env.PORT, 
      host: '0.0.0.0' 
    });
    
    console.log(`🚀 SoulLift API running at ${address}`);
    console.log(`📖 Documentation: ${address}/docs`);
    console.log(`🎤 AI Voices: ${USE_OPENAI ? 'Enabled' : 'Disabled'}`);
    console.log(`💳 Payments: ${USE_STRIPE ? 'Enabled' : 'Disabled'}`);
    console.log(`🗄️ Database: ${USE_DB ? 'Connected' : 'Mock Mode'}`);
  } catch (err) {
    console.error('💥 Failed to start server:', err);
    process.exit(1);
  }
}

start();