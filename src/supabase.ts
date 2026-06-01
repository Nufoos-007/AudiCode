import { createClient, SupabaseClient } from '@supabase/supabase-js';

let supabaseInstance: SupabaseClient | null = null;
let initPromise: Promise<SupabaseClient> | null = null;

/**
 * Singleton getter to resolve and initialize Supabase client instance.
 * Fetches configured credentials dynamically from /api/config.
 */
export async function getSupabase(): Promise<SupabaseClient> {
  if (supabaseInstance) return supabaseInstance;
  if (initPromise) return initPromise;

  initPromise = (async () => {
    try {
      // Prioritize client-side environment variables for seamless serverless static hosting (e.g., on Vercel)
      const viteUrl = import.meta.env.VITE_SUPABASE_URL;
      const viteKey = import.meta.env.VITE_SUPABASE_ANON_KEY;

      if (viteUrl && viteKey) {
        console.log('Initializing Supabase client using client-side environment variables.');
        supabaseInstance = createClient(viteUrl, viteKey, {
          auth: {
            persistSession: true,
            autoRefreshToken: true,
            detectSessionInUrl: true
          }
        });
        return supabaseInstance;
      }

      const baseUrl = import.meta.env.VITE_API_URL || '';
      const configUrl = baseUrl ? `${baseUrl}/api/config` : '/api/config';
      
      const res = await fetch(configUrl);
      if (!res.ok) {
        throw new Error(`Config fetch failed: ${res.status}`);
      }
      const data = await res.json();
      const url = data.supabaseUrl || '';
      const key = data.supabaseAnonKey || '';

      if (!url || !key) {
        console.warn('Supabase URL or Anon Key is missing from system configuration.');
      }

      supabaseInstance = createClient(url, key, {
        auth: {
          persistSession: true,
          autoRefreshToken: true,
          detectSessionInUrl: true
        }
      });
      return supabaseInstance;
    } catch (err) {
      console.error('Failed to initialize Supabase client:', err);
      // Fallback instance to prevent crash
      supabaseInstance = createClient('https://placeholder.supabase.co', 'placeholder-anon-key');
      return supabaseInstance;
    }
  })();

  return initPromise;
}
