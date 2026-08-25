import AsyncStorage from "@react-native-async-storage/async-storage";
import { createClient } from "@supabase/supabase-js";

const url = process.env.EXPO_PUBLIC_SUPABASE_URL?.trim() ?? "";
const publishableKey = (
  process.env.EXPO_PUBLIC_SUPABASE_PUBLISHABLE_KEY
  ?? process.env.EXPO_PUBLIC_SUPABASE_ANON_KEY
)?.trim() ?? "";

export const isCloudConfigured = Boolean(url && publishableKey && !url.includes("PROJE_KODUNUZ"));

export const supabase = createClient(
  url || "https://placeholder.supabase.co",
  publishableKey || "placeholder",
  {
    auth: {
      storage: AsyncStorage,
      autoRefreshToken: true,
      persistSession: true,
      detectSessionInUrl: false,
    },
  },
);

export function normalizeUsername(username: string) {
  return username
    .trim()
    .toLocaleLowerCase("tr-TR")
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/ı/g, "i")
    .replace(/[^a-z0-9._-]/g, "");
}

export function usernameToInternalEmail(username: string) {
  const normalized = normalizeUsername(username);
  return normalized ? `${normalized}@stokta.invalid` : "";
}
