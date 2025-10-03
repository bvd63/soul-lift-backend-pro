// generate_ai_quotes.js
import fs from "fs";
import fetch from "node-fetch";
import cron from "node-cron";

const OPENAI_KEY = process.env.OPENAI_API_KEY || "";
const AI_FILE = "./data/ai_quotes.json";

// categorii suportate
const CATEGORIES = [
  "motivation","focus","calm","gratitude","success","love",
  "wisdom","hustle","stoicism","mindset","healing","life",
  "discipline","courage","creativity"
];

// generator AI
async function aiGenerateQuote(category, lang="EN", tone="inspiring", maxChars=120) {
  const res = await fetch("https://api.openai.com/v1/chat/completions", {
    method:"POST",
    headers:{ Authorization:`Bearer ${OPENAI_KEY}`, "Content-Type":"application/json" },
    body: JSON.stringify({
      model: "gpt-4o-mini",
      temperature: 0.8,
      messages: [
        { role:"system", content:`Write an original motivational quote under ${maxChars} chars in ${lang}. No author names.` },
        { role:"user", content:`Theme: ${category}, Tone: ${tone}` }
      ]
    })
  });
  if(!res.ok) throw new Error("OpenAI failed");
  const d = await res.json();
  return d?.choices?.[0]?.message?.content?.trim() || null;
}

// funcția principală
async function generateBatch(count=50) {
  let existing = [];
  if (fs.existsSync(AI_FILE)) {
    existing = JSON.parse(fs.readFileSync(AI_FILE,"utf-8"));
  }

  const out = [...existing];
  for (let i=0; i<count; i++) {
    const cat = CATEGORIES[Math.floor(Math.random()*CATEGORIES.length)];
    try {
      const q = await aiGenerateQuote(cat,"EN","inspiring");
      if (q) {
        out.push({ text:q, category:cat, lang:"EN", createdAt: Date.now() });
        console.log("✅ Generated:", q);
      }
    } catch(e) {
      console.error("❌ Error:", e.message);
    }
    await new Promise(r => setTimeout(r, 2000)); // mică pauză anti-rate limit
  }

  fs.writeFileSync(AI_FILE, JSON.stringify(out,null,2));
  console.log("🎉 Done. Total quotes:", out.length);
}

// rulează o dată la pornire
await generateBatch(50);

// rulează zilnic la 03:00 dimineața (server time)
cron.schedule("0 3 * * *", async () => {
  console.log("🌙 Night job: generating daily quotes...");
  await generateBatch(50);
});
