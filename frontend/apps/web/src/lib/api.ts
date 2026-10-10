import { createClient } from "@quantumtrace/sdk";

export const API_URL: string = import.meta.env.VITE_API_URL ?? "http://localhost:8000";

export const api = createClient({
  baseUrl: API_URL,
  apiKey: import.meta.env.VITE_API_KEY || undefined,
});
