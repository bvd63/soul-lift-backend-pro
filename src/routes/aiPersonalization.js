// src/routes/aiPersonalization.js - Endpoint pentru personalizarea citatelor cu AI
// Oferă funcționalități avansate de personalizare a citatelor folosind AI

import validator from '../utils/validator.js';
import apiRetry from '../utils/apiRetry.js';
import redisClient from '../services/redisClient.js';
import fs from 'fs';

/**
 * Înregistrează rutele pentru personalizarea citatelor cu AI
 * @param {FastifyInstance} fastify - Instanța Fastify
 */
export default async function (fastify, options) {
  const { db, openaiApiKey, authMiddleware } = fastify;

  // Schema de validare pentru personalizarea citatelor
  const personalizeSchema = {
    body: {
      type: validator.TYPES.OBJECT,
      properties: {
        preferences: {
          type: validator.TYPES.ARRAY,
          items: {
            type: validator.TYPES.STRING
          },
          minItems: 1,
          maxItems: 5
        },
        topics: {
          type: validator.TYPES.ARRAY,
          items: {
            type: validator.TYPES.STRING
          },
          minItems: 1,
          maxItems: 5
        },
        style: {
          type: validator.TYPES.STRING,
          default: 'motivational'
        },
        length: {
          type: validator.TYPES.STRING,
          enum: ['short', 'medium', 'long'],
          default: 'medium'
        },
        language: {
          type: validator.TYPES.STRING,
          default: 'ro'
        }
      },
      required: ['preferences', 'topics']
    }
  };

  // Endpoint pentru personalizarea citatelor
  fastify.post('/api/quotes/personalize', {
    preHandler: [authMiddleware, validator.validateRequest(personalizeSchema)]
  }, async (request, reply) => {
    try {
      const { preferences, topics, style, length, language } = request.body;
      const userId = request.user.id;

      // Generăm un ID unic pentru acest apel
      const requestId = `personalize-${userId}-${Date.now()}`;
      
      // Verificăm cache-ul pentru a evita generări redundante
      const cacheKey = `personalize-${userId}-${JSON.stringify(preferences)}-${JSON.stringify(topics)}-${style}-${length}-${language}`;
      const cachedResponse = await redisClient.get(cacheKey);
      
      if (cachedResponse) {
        // Înregistrăm utilizarea cache-ului
        await db.query(
          'INSERT INTO audit_log (user_id, action, details) VALUES ($1, $2, $3)',
          [userId, 'quote_personalize_cache', JSON.stringify({ requestId, preferences, topics })]
        );
        
        return cachedResponse;
      }

      // Obținem istoricul de citate favorite ale utilizatorului pentru context
      const favoriteQuotesResult = await db.query(
        'SELECT q.text FROM favorites f JOIN ai_quotes q ON f.quote_id = q.id WHERE f.user_id = $1 ORDER BY f.created_at DESC LIMIT 5',
        [userId]
      );
      
      const favoriteQuotes = favoriteQuotesResult.rows.map(row => row.text);

      // Construim prompt-ul pentru OpenAI
      const lengthMap = {
        short: '30-50 caractere',
        medium: '80-120 caractere',
        long: '150-200 caractere'
      };

      const prompt = `Generează un citat motivațional personalizat cu următoarele caracteristici:
- Preferințe utilizator: ${preferences.join(', ')}
- Teme de interes: ${topics.join(', ')}
- Stil: ${style}
- Lungime: ${lengthMap[length]}
- Limba: ${language === 'ro' ? 'română' : language === 'en' ? 'engleză' : language}

${favoriteQuotes.length > 0 ? `Citate favorite ale utilizatorului (pentru context):
${favoriteQuotes.map((q, i) => `${i+1}. "${q}"`).join('\n')}` : ''}

Răspunde doar cu citatul generat, fără ghilimele sau alte explicații.`;

      // Facem apelul către OpenAI cu sistemul de retry
      const openaiResponse = await apiRetry.fetchWithRetry('https://api.openai.com/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${openaiApiKey}`
        },
        body: JSON.stringify({
          model: 'gpt-4',
          messages: [
            { role: 'system', content: 'Ești un expert în generarea de citate motivaționale personalizate.' },
            { role: 'user', content: prompt }
          ],
          temperature: 0.7,
          max_tokens: 200
        })
      }, {
        maxRetries: 3,
        logRetries: true
      });

      const logFile = './logs/openai_debug.log';
      const logMessage = `\nPrompt trimis către OpenAI: ${prompt}\nRăspuns complet OpenAI: ${JSON.stringify(openaiResponse, null, 2)}\n`;
      fs.appendFileSync(logFile, logMessage);
      if (!openaiResponse || !openaiResponse.choices || !openaiResponse.choices[0]) {
        fs.appendFileSync(logFile, `Răspuns OpenAI invalid sau gol: ${JSON.stringify(openaiResponse, null, 2)}\n`);
      } else {
        fs.appendFileSync(logFile, `Citat generat: ${openaiResponse.choices[0].message.content.trim()}\n`);
      }
      
      // Extragem citatul generat
      const generatedQuote = openaiResponse.choices[0].message.content.trim();
      console.log('Citat generat:', generatedQuote);

      // Salvăm citatul în baza de date
      const insertResult = await db.query(
        'INSERT INTO ai_quotes (text, category, lang, score, user_generated, user_id) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id',
        [generatedQuote, topics[0], language, 0, true, userId]
      );
      
      const quoteId = insertResult.rows[0].id;

      // Înregistrăm acțiunea în audit log
      await db.query(
        'INSERT INTO audit_log (user_id, action, details) VALUES ($1, $2, $3)',
        [userId, 'quote_personalize', JSON.stringify({ requestId, quoteId, preferences, topics })]
      );

      // Construim răspunsul
      const response = {
        id: quoteId,
        text: generatedQuote,
        category: topics[0],
        language: language,
        personalized: true,
        preferences: preferences,
        topics: topics
      };

      // Salvăm în cache în Redis pentru utilizări viitoare (1 oră)
      await redisClient.set(cacheKey, response, 3600);

      return response;
    } catch (error) {
      console.error('Eroare la personalizarea citatului:', error);
      
      // Înregistrăm eroarea
      if (request.user && request.user.id) {
        await db.query(
          'INSERT INTO audit_log (user_id, action, details) VALUES ($1, $2, $3)',
          [request.user.id, 'quote_personalize_error', JSON.stringify({ error: error.message })]
        );
      }
      
      reply.code(500).send({ error: 'Eroare la personalizarea citatului', details: error.message });
    }
  });

  // Endpoint pentru obținerea istoricului de citate personalizate
  fastify.get('/api/quotes/personalized', {
    preHandler: [authMiddleware]
  }, async (request, reply) => {
    try {
      const userId = request.user.id;
      
      const result = await db.query(
        'SELECT id, text, category, lang, created_at FROM ai_quotes WHERE user_generated = true AND user_id = $1 ORDER BY created_at DESC LIMIT 20',
        [userId]
      );
      
      return {
        count: result.rows.length,
        quotes: result.rows
      };
    } catch (error) {
      console.error('Eroare la obținerea citatelor personalizate:', error);
      reply.code(500).send({ error: 'Eroare la obținerea citatelor personalizate', details: error.message });
    }
  });
}
