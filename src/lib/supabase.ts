import { createClient } from "@supabase/supabase-js";

const supabaseUrl = import.meta.env.VITE_SUPABASE_URL;
const supabaseAnonKey = import.meta.env.VITE_SUPABASE_ANON_KEY;

export const supabase = createClient(supabaseUrl, supabaseAnonKey);

export const signInWithGitHub = async () => {
  // First, sign out and clear everything
  await supabase.auth.signOut();
  sessionStorage.clear();
  localStorage.clear();
  
  // Use Supabase OAuth - it will handle the flow
  const { data, error } = await supabase.auth.signInWithOAuth({
    provider: "github",
    options: {
      redirectTo: window.location.origin + "/dashboard?fresh_login=true",
    },
  });
  
  if (error) {
    // If OAuth URL was returned, redirect manually
    if (data.url) {
      window.location.href = data.url;
    } else {
      throw error;
    }
  }
};

export const signInWithGoogle = async () => {
  // First, sign out and clear everything
  await supabase.auth.signOut();
  sessionStorage.clear();
  localStorage.clear();
  
  const { data, error } = await supabase.auth.signInWithOAuth({
    provider: "google",
    options: {
      redirectTo: window.location.origin + "/dashboard?fresh_login=true",
      queryParams: {
        prompt: "select_account",
      },
    },
  });
  
  if (error) {
    if (data.url) {
      window.location.href = data.url;
    } else {
      throw error;
    }
  }
};

export const signOut = async () => {
  sessionStorage.clear();
  localStorage.clear();
  
  const { error } = await supabase.auth.signOut();
  if (error) throw error;
  
  window.location.href = "/";
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