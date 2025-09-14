import LRU from "lru-cache";

const cache = new LRU<string, {text:string, ts:number}>({
  max: 500,
  ttl: 1000 * 60 * 30, // 30 min
});

export function cacheGet(key: string){
  const v = cache.get(key);
  if (!v) return null;
  return v.text;
}
export function cacheSet(key: string, text: string){
  cache.set(key, {text, ts: Date.now()});
}
