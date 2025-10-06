// src/routes/aiRecommendations.js - Sistem de recomandări bazat pe AI
// Oferă recomandări personalizate de citate folosind AI și analiza comportamentului utilizatorului

import validator from '../utils/validator.js';
import apiRetry from '../utils/apiRetry.js';
import redisClient from '../services/redisClient.js';

/**
 * Înregistrează rutele pentru sistemul de recomandări bazat pe AI
 * @param {FastifyInstance} fastify - Instanța Fastify
 */
export default async function (fastify, options) {
  const { db, openaiApiKey, authMiddleware, logger } = fastify;

  // Endpoint pentru obținerea recomandărilor personalizate
  fastify.get('/api/quotes/recommendations', {
    preHandler: [authMiddleware]
  }, async (request, reply) => {
    try {
      const userId = request.user.id;
      const count = parseInt(request.query.count) || 5;
      
      // Generăm un ID unic pentru acest apel
      const requestId = `recommendations-${userId}-${Date.now()}`;
      
      // Verificăm cache-ul pentru a evita generări redundante
      const cacheKey = `recommendations-${userId}-${count}`;
      const cachedResponse = await redisClient.get(cacheKey);
      
      if (cachedResponse) {
        logger.info('Recomandări obținute din cache', { requestId, userId });
        return cachedResponse;
      }

      // Obținem datele utilizatorului pentru a construi profilul
      const userResult = await db.query(
        'SELECT id, name, email, created_at, login_streak, total_logins FROM users WHERE id = $1',
        [userId]
      );
      
      if (userResult.rows.length === 0) {
        reply.code(404).send({ error: 'Utilizator negăsit' });
        return;
      }
      
      const user = userResult.rows[0];

      // Obținem citatele favorite ale utilizatorului
      const favoritesResult = await db.query(
        'SELECT q.id, q.text, q.category, q.lang FROM favorites f JOIN ai_quotes q ON f.quote_id = q.id WHERE f.user_id = $1 ORDER BY f.created_at DESC LIMIT 10',
        [userId]
      );
      
      const favorites = favoritesResult.rows;

      // Obținem citatele personalizate generate anterior
      const personalizedResult = await db.query(
        'SELECT id, text, category, lang FROM ai_quotes WHERE user_generated = true AND user_id = $1 ORDER BY created_at DESC LIMIT 5',
        [userId]
      );
      
      const personalized = personalizedResult.rows;

      // Obținem categoriile cele mai accesate
      const categoriesResult = await db.query(
        'SELECT category, COUNT(*) as count FROM audit_log WHERE user_id = $1 AND action = \'quote_view\' AND details->\'category\' IS NOT NULL GROUP BY category ORDER BY count DESC LIMIT 5',
        [userId]
      );
      
      const topCategories = categoriesResult.rows.map(row => row.category);

      // Construim profilul utilizatorului
      const userProfile = {
        loginStreak: user.login_streak,
        totalLogins: user.total_logins,
        accountAge: Math.floor((Date.now() - new Date(user.created_at).getTime()) / (1000 * 60 * 60 * 24)),
        favoriteCategories: topCategories,
        favoriteQuotes: favorites.map(q => ({ text: q.text, category: q.category, language: q.lang })),
        personalizedQuotes: personalized.map(q => ({ text: q.text, category: q.category, language: q.lang }))
      };

      // Obținem citate care ar putea fi relevante pentru utilizator
      const relevantQuotesResult = await db.query(
        'SELECT id, text, category, lang FROM ai_quotes WHERE category = ANY($1) AND lang = $2 ORDER BY RANDOM() LIMIT 20',
        [topCategories.length > 0 ? topCategories : ['Motivation'], request.user.lang || 'ro']
      );
      
      const relevantQuotes = relevantQuotesResult.rows;

      // Construim prompt-ul pentru OpenAI
      const prompt = `Analizează profilul utilizatorului și recomandă ${count} citate motivaționale care s-ar potrivi cel mai bine cu preferințele și comportamentul său.

Profil utilizator:
- Zile consecutive de login: ${userProfile.loginStreak}
- Total login-uri: ${userProfile.totalLogins}
- Vechime cont: ${userProfile.accountAge} zile
- Categorii preferate: ${userProfile.favoriteCategories.join(', ') || 'Necunoscute'}

Citate favorite anterioare:
${userProfile.favoriteQuotes.map(q => `- "${q.text}" (${q.category})`).join('\n')}

Citate personalizate generate anterior:
${userProfile.personalizedQuotes.map(q => `- "${q.text}" (${q.category})`).join('\n')}

Citate disponibile pentru recomandare:
${relevantQuotes.map((q, i) => `${i+1}. "${q.text}" (${q.category})`).join('\n')}

Răspunde cu numerele citatelor recomandate (din lista de citate disponibile) și o scurtă explicație pentru fiecare recomandare. Formatul răspunsului trebuie să fie:
1. <număr citat> - <explicație>
2. <număr citat> - <explicație>
...`;

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
            { role: 'system', content: 'Ești un expert în recomandări personalizate de citate motivaționale.' },
            { role: 'user', content: prompt }
          ],
          temperature: 0.7,
          max_tokens: 500
        })
      }, {
        maxRetries: 3,
        logRetries: true
      });

      // Procesăm răspunsul pentru a extrage recomandările
      const aiResponse = openaiResponse.choices[0].message.content.trim();
      const recommendations = [];
      
      // Parsăm răspunsul pentru a extrage numerele citatelor și explicațiile
      const recommendationLines = aiResponse.split('\n');
      for (const line of recommendationLines) {
        const match = line.match(/^(\d+)\.\s+(\d+)\s+-\s+(.+)$/);
        if (match) {
          const quoteIndex = parseInt(match[2]) - 1;
          const explanation = match[3].trim();
          
          if (quoteIndex >= 0 && quoteIndex < relevantQuotes.length) {
            const quote = relevantQuotes[quoteIndex];
            recommendations.push({
              id: quote.id,
              text: quote.text,
              category: quote.category,
              language: quote.lang,
              explanation: explanation
            });
          }
        }
      }

      // Dacă nu am reușit să extragem suficiente recomandări, adăugăm citate aleatorii
      while (recommendations.length < count && relevantQuotes.length > 0) {
        const randomIndex = Math.floor(Math.random() * relevantQuotes.length);
        const quote = relevantQuotes[randomIndex];
        
        // Verificăm dacă citatul nu este deja în recomandări
        if (!recommendations.some(r => r.id === quote.id)) {
          recommendations.push({
            id: quote.id,
            text: quote.text,
            category: quote.category,
            language: quote.lang,
            explanation: 'Recomandat pe baza preferințelor tale'
          });
        }
        
        // Eliminăm citatul din lista de citate disponibile
        relevantQuotes.splice(randomIndex, 1);
      }

      // Înregistrăm acțiunea în audit log
      await db.query(
        'INSERT INTO audit_log (user_id, action, details) VALUES ($1, $2, $3)',
        [userId, 'quote_recommendations', JSON.stringify({ requestId, count, recommendationIds: recommendations.map(r => r.id) })]
      );

      // Construim răspunsul
      const response = {
        count: recommendations.length,
        recommendations: recommendations
      };

      // Salvăm în cache în Redis pentru utilizări viitoare (15 minute)
      await redisClient.set(cacheKey, response, 15 * 60);

      return response;
    } catch (error) {
      logger.error('Eroare la generarea recomandărilor', error);
      
      // Înregistrăm eroarea
      if (request.user && request.user.id) {
        await db.query(
          'INSERT INTO audit_log (user_id, action, details) VALUES ($1, $2, $3)',
          [request.user.id, 'quote_recommendations_error', JSON.stringify({ error: error.message })]
        );
      }
      
      reply.code(500).send({ error: 'Eroare la generarea recomandărilor', details: error.message });
    }
  });

  // Endpoint pentru feedback la recomandări
  fastify.post('/api/quotes/recommendations/feedback', {
    preHandler: [authMiddleware, validator.validateRequest({
      body: {
        type: validator.TYPES.OBJECT,
        properties: {
          quoteId: {
            type: validator.TYPES.STRING,
            required: true
          },
          feedback: {
            type: validator.TYPES.STRING,
            enum: ['like', 'dislike', 'neutral'],
            required: true
          },
          details: {
            type: validator.TYPES.STRING
          }
        }
      }
    })]
  }, async (request, reply) => {
    try {
      const { quoteId, feedback, details } = request.body;
      const userId = request.user.id;
      
      // Verificăm dacă citatul există
      const quoteResult = await db.query(
        'SELECT id FROM ai_quotes WHERE id = $1',
        [quoteId]
      );
      
      if (quoteResult.rows.length === 0) {
        reply.code(404).send({ error: 'Citat negăsit' });
        return;
      }
      
      // Înregistrăm feedback-ul
      await db.query(
        'INSERT INTO audit_log (user_id, action, details) VALUES ($1, $2, $3)',
        [userId, 'quote_recommendation_feedback', JSON.stringify({ quoteId, feedback, details })]
      );
      
      // Dacă feedback-ul este pozitiv, adăugăm citatul la favorite
      if (feedback === 'like') {
        // Verificăm dacă citatul este deja în favorite
        const favoriteResult = await db.query(
          'SELECT id FROM favorites WHERE user_id = $1 AND quote_id = $2',
          [userId, quoteId]
        );
        
        if (favoriteResult.rows.length === 0) {
          await db.query(
            'INSERT INTO favorites (user_id, quote_id) VALUES ($1, $2)',
            [userId, quoteId]
          );
        }
      }
      
      // Invalidăm cache-ul pentru recomandări
      const cacheKeys = memoryCache.getKeys().filter(key => key.startsWith(`recommendations-${userId}`));
      for (const key of cacheKeys) {
        memoryCache.del(key);
      }
      
      return { success: true };
    } catch (error) {
      logger.error('Eroare la înregistrarea feedback-ului', error);
      reply.code(500).send({ error: 'Eroare la înregistrarea feedback-ului', details: error.message });
    }
  });
}
