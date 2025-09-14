import OpenAI from "openai";

const client = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY,
});

export async function getQuoteFromOpenAI(prompt: string){
  // Basic retry with backoff
  let attempt = 0;
  let lastErr: any;
  while (attempt < 3){
    try{
      const r = await client.chat.completions.create({
        model: "gpt-4o-mini",
        messages: [{role:"user", content: prompt}],
        max_tokens: 60,
      });
      const text = r.choices?.[0]?.message?.content?.trim();
      if (text) return text;
      throw new Error("Empty completion");
    }catch(e){
      lastErr = e;
      await new Promise(res=>setTimeout(res, 300 * Math.pow(2, attempt)));
      attempt++;
    }
  }
  throw lastErr;
}
