import { createClient } from "@supabase/supabase-js";

const supabaseUrl = import.meta.env.VITE_SUPABASE_URL;
const supabaseAnonKey = import.meta.env.VITE_SUPABASE_ANON_KEY;

export const supabase = createClient(supabaseUrl, supabaseAnonKey);

export const signInWithGitHub = async () => {
  // Clear all auth data first to force fresh login
  await supabase.auth.signOut();
  
  const { data, error } = await supabase.auth.signInWithOAuth({
    provider: "github",
    options: {
      redirectTo: window.location.origin + "/dashboard",
    },
  });
  if (error) throw error;
  return data;
};

export const signInWithGoogle = async () => {
  // Clear all auth data first to force fresh login
  await supabase.auth.signOut();
  
  const { data, error } = await supabase.auth.signInWithOAuth({
    provider: "google",
    options: {
      redirectTo: window.location.origin + "/dashboard",
    },
  });
  if (error) throw error;
  return data;
};

export const signOut = async () => {
  // Clear everything - session storage, local storage, and Supabase session
  sessionStorage.clear();
  localStorage.clear();
  
  const { error } = await supabase.auth.signOut();
  if (error) throw error;
  
  // Force page reload to clear any cached state
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