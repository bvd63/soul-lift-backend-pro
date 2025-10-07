// SoulLift Voice Service
// Handles AI voice selection and TTS generation

import { fetchWithRetry } from '../utils/apiRetry.js';

// Voice profiles with personality mapping
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

// Map human voice names to OpenAI TTS voices
const voiceMapping = {
  // Feminine voices
  'sophia_calm': 'nova', 'maria_energetic': 'shimmer', 'elena_wise': 'alloy',
  'anna_confident': 'nova', 'julia_nurturing': 'shimmer', 'clara_inspiring': 'alloy',
  'luna_peaceful': 'nova', 'maya_powerful': 'shimmer', 'zara_gentle': 'alloy',
  'nova_dynamic': 'nova',
  // Masculine voices  
  'david_strong': 'onyx', 'marcus_motivational': 'echo', 'alex_calm': 'fable',
  'erik_confident': 'onyx', 'leo_inspiring': 'echo', 'noah_grounded': 'fable',
  'kai_energetic': 'echo', 'finn_wise': 'onyx', 'zane_powerful': 'echo',
  'ace_gentle': 'fable'
};

// Voice descriptions for user display
const voiceDescriptions = {
  'sophia_calm': 'Calm and nurturing feminine voice',
  'maria_energetic': 'Energetic and motivational feminine voice',
  'elena_wise': 'Wise and thoughtful feminine voice',
  'anna_confident': 'Confident and strong feminine voice',
  'julia_nurturing': 'Warm and caring feminine voice',
  'clara_inspiring': 'Inspiring and uplifting feminine voice',
  'luna_peaceful': 'Peaceful and serene feminine voice',
  'maya_powerful': 'Powerful and dynamic feminine voice',
  'zara_gentle': 'Gentle and soothing feminine voice',
  'nova_dynamic': 'Dynamic and versatile feminine voice',
  'david_strong': 'Strong and authoritative masculine voice',
  'marcus_motivational': 'Motivational and inspiring masculine voice',
  'alex_calm': 'Calm and reassuring masculine voice',
  'erik_confident': 'Confident and bold masculine voice',
  'leo_inspiring': 'Inspiring and uplifting masculine voice',
  'noah_grounded': 'Grounded and stable masculine voice',
  'kai_energetic': 'Energetic and enthusiastic masculine voice',
  'finn_wise': 'Wise and thoughtful masculine voice',
  'zane_powerful': 'Powerful and commanding masculine voice',
  'ace_gentle': 'Gentle and warm masculine voice'
};

// AI-powered voice selection
export async function selectOptimalVoice(quote, subscriptionTier) {
  try {
    const text = quote.text.toLowerCase();
    const tags = quote.tags || [];
    
    // Determine mood category
    let moodCategory = 'motivational';
    if (text.match(/peace|calm|serene|tranquil|quiet|gentle/i) || tags.includes('peace')) {
      moodCategory = 'peaceful';
    } else if (text.match(/wisdom|understand|learn|reflect|think/i) || tags.includes('wisdom')) {
      moodCategory = 'wise';
    } else if (text.match(/confident|strong|powerful|bold|courage/i) || tags.includes('confidence')) {
      moodCategory = 'confident';
    }
    
    const genderPreference = Math.random() > 0.5 ? 'feminine' : 'masculine';
    const voiceOptions = voiceProfiles[genderPreference][moodCategory] || 
                        voiceProfiles[genderPreference]['motivational'];
    
    // Pro users get all voices, Standard users get limited selection
    const availableVoices = subscriptionTier === 'pro' ? voiceOptions : voiceOptions.slice(0, 2);
    return availableVoices[Math.floor(Math.random() * availableVoices.length)];
  } catch (e) {
    return 'sophia_calm'; // fallback
  }
}

// Generate audio using OpenAI TTS
export async function generateHumanVoiceAudio(text, voice, subscriptionTier, speed = 1.0, format = 'mp3') {
  try {
    const openaiVoice = voiceMapping[voice] || 'alloy';
    const model = subscriptionTier === 'pro' ? 'tts-1-hd' : 'tts-1';
    
    const response = await fetch('https://api.openai.com/v1/audio/speech', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${process.env.OPENAI_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        model,
        input: text,
        voice: openaiVoice,
        speed,
        response_format: format
      })
    });
    
    if (!response.ok) {
      const error = await response.text();
      throw new Error(`TTS API error: ${error}`);
    }
    
    const audioBuffer = await response.arrayBuffer();
    const estimatedDuration = Math.ceil(text.length / 12); // ~12 chars per second estimate
    
    return {
      success: true,
      audioBuffer: Buffer.from(audioBuffer),
      duration: estimatedDuration,
      contentType: format === 'mp3' ? 'audio/mpeg' : 'audio/wav'
    };
  } catch (e) {
    console.error('Voice generation failed:', e);
    return { success: false, error: e.message };
  }
}

// Get voice description for display
export function getVoiceDescription(voice) {
  return voiceDescriptions[voice] || 'Human-like AI voice';
}

// Get all available voices for tier
export function getAvailableVoices(subscriptionTier) {
  const allVoices = Object.keys(voiceMapping);
  
  if (subscriptionTier === 'pro') {
    return allVoices;
  } else if (subscriptionTier === 'standard') {
    // Standard users get 6 voices (3 feminine + 3 masculine)
    return [
      'sophia_calm', 'maria_energetic', 'elena_wise',
      'david_strong', 'marcus_motivational', 'alex_calm'
    ];
  } else {
    return []; // Free users get no voices
  }
}

export default {
  selectOptimalVoice,
  generateHumanVoiceAudio,
  getVoiceDescription,
  getAvailableVoices
};
