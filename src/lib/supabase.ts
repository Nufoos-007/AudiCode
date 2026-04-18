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
  const redirectTo = window.location.origin + "/auth?loggedin=1";
  const authUrl = `https://bkpifjpeaitfoiqulgaw.supabase.co/auth/v1/authorize?provider=github&redirect_to=${encodeURIComponent(redirectTo)}`;
  window.location.href = authUrl;
};

export const signInWithGoogle = async () => {
  const redirectTo = window.location.origin + "/auth?loggedin=1";
  const authUrl = `https://bkpifjpeaitfoiqulgaw.supabase.co/auth/v1/authorize?provider=google&redirect_to=${encodeURIComponent(redirectTo)}`;
  window.location.href = authUrl;
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