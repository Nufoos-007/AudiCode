import { createClient } from "@supabase/supabase-js";

const supabaseUrl = import.meta.env.VITE_SUPABASE_URL;
const supabaseAnonKey = import.meta.env.VITE_SUPABASE_ANON_KEY;

export const supabase = createClient(supabaseUrl, supabaseAnonKey);

function clearAllAuthData() {
  sessionStorage.clear();
  localStorage.clear();
  document.cookie.split(";").forEach(c => {
    document.cookie = c.replace(/^ +/, "").replace(/=.*/, "=;expires=" + new Date().toUTCString() + ";path=/");
  });
}

export const signInWithGitHub = async () => {
  clearAllAuthData();
  await supabase.auth.signOut();
  
  const { data, error } = await supabase.auth.signInWithOAuth({
    provider: "github",
    options: {
      redirectTo: window.location.origin + "/dashboard",
      scopes: "repo",
      skipRedirectNonce: true,
    },
  });
  
  if (error) throw error;
  if (data.url) window.location.href = data.url;
};

export const signInWithGoogle = async () => {
  clearAllAuthData();
  await supabase.auth.signOut();
  
  const { data, error } = await supabase.auth.signInWithOAuth({
    provider: "google",
    options: {
      redirectTo: window.location.origin + "/dashboard",
    },
  });
  
  if (error) throw error;
  if (data.url) window.location.href = data.url;
};

export const signOut = async () => {
  clearAllAuthData();
  await supabase.auth.signOut();
  sessionStorage.clear();
  localStorage.removeItem("supabase.auth.token");
  sessionStorage.removeItem("supabase.auth.refresh_token");
  window.location.replace(window.location.origin);
};

export const getSession = async () => {
  const { data: { session }, error } = await supabase.auth.getSession();
  if (error) throw error;
  return session;
};

export const getCurrentUser = async () => {
  const { data: { user }, error } = await supabase.auth.getUser();
  if (error) return null;
  return user;
};

export const onAuthStateChange = (callback: (event: string, session: any) => void) => {
  return supabase.auth.onAuthStateChange(callback);
};