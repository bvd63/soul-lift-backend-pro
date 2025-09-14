import { z } from "zod";

export const QuoteQuery = z.object({
  lang: z.string().min(2).max(10).default("ro"),
  category: z.enum(["motivation","anxiety","confidence","relaxation","hope"]).default("motivation")
});

export type QuoteQuery = z.infer<typeof QuoteQuery>;

export type QuoteResponse = {
  lang: string;
  category: string;
  text: string;
  cached: boolean;
};
