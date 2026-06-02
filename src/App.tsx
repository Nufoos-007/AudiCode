import React, { useState, useEffect } from 'react';
import { RefreshCw } from 'lucide-react';
import { LoginView } from './components/LoginView';
import { DashboardView } from './components/DashboardView';
import { GitHubUser } from './types';
import { getSupabase } from './supabase';
import { apiFetch } from './utils/api';

type PageState = 'INITIAL_CHECK' | 'LOGIN' | 'DASHBOARD';

export default function App() {
  const [page, setPage] = useState<PageState>('INITIAL_CHECK');
  const [user, setUser] = useState<GitHubUser | null>(null);

  const [supabaseClient, setSupabaseClient] = useState<any>(null);

  useEffect(() => {
    getSupabase().then(client => {
      setSupabaseClient(client);
    });
  }, []);

  useEffect(() => {
    if (!supabaseClient) return;

    // Track active auth subscription shift state
    const { data: { subscription } } = supabaseClient.auth.onAuthStateChange(async (event: string, session: any) => {
      console.log('App Supabase auth state change event:', event);
      
      if (session) {
        const metadata = session.user.user_metadata || {};
        // Recover provider token from session, falling back to localStorage if it is absent (as Supabase does not persist transient provider_token in the stored session across page reloads)
        const providerToken = session.provider_token || window.localStorage.getItem('audi_sb_provider_token') || '';

        if (!providerToken) {
          console.warn('[AUTH] Provider token missing in active session. Evicting stale caches and triggering clean re-authentication.');
          window.localStorage.removeItem('audi_sb_access_token');
          window.localStorage.removeItem('audi_sb_provider_token');
          try {
            await supabaseClient.auth.signOut();
          } catch (err) {
            console.error('[AUTH] Sign out error:', err);
          }
          setUser(null);
          setPage('LOGIN');
          return;
        }

        const githubUser: GitHubUser = {
          id: session.user.id,
          login: metadata.preferred_username || metadata.user_name || session.user.email?.split('@')[0] || 'github_user',
          name: metadata.full_name || metadata.name || metadata.user_name || 'GitHub User',
          avatarUrl: metadata.avatar_url || 'data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><circle cx="50" cy="50" r="50" fill="%231f242c"/><path d="M50,85 C25,85 15,67 15,60 C15,53 25,43 50,43 C75,43 85,53 85,60 C85,67 75,85 50,85 Z" fill="%238b949e"/><circle cx="50" cy="27" r="14" fill="%238b949e"/></svg>',
          accessToken: providerToken
        };

        window.localStorage.setItem('audi_sb_access_token', session.access_token);
        window.localStorage.setItem('audi_sb_provider_token', providerToken);

        setUser(githubUser);
        setPage('DASHBOARD');
      } else {
        // If this is currently a guest sandbox session, we do not force-evict it
        setUser((currentUser) => {
          if (currentUser?.id === 'guest-dev') {
            return currentUser;
          } else {
            // Only clear the tokens when explicitly signed out or fully unauthenticated
            if (event === 'SIGNED_OUT') {
              window.localStorage.removeItem('audi_sb_access_token');
              window.localStorage.removeItem('audi_sb_provider_token');
              setPage('LOGIN');
              return null;
            }
            return currentUser;
          }
        });
      }
    });

    // Also verify active session from headers just in case localStorage has old values.
    // To prevent a race condition during sign-in redirects, we skip backend query if we observe an incoming OAuth session in URL.
    const queryActiveSessionOnBoot = async () => {
      const hasIncomingOAuthSession = window.location.hash.includes('access_token=') || window.location.search.includes('access_token=');
      if (hasIncomingOAuthSession) {
        console.log('Detected incoming OAuth redirect session. Handing auth flow to Supabase onAuthStateChange.');
        return;
      }

      try {
        const res = await apiFetch('/api/auth/session');
        const data = await res.json();
        if (data.isAuthenticated && data.user) {
          // If the backend returned a user, but it didn't verify a valid provider token (e.g., accessToken is empty or invalid):
          if (!data.user.accessToken) {
            console.warn('[AUTH] Boot session has no verified active provider token. Forcing clean login.');
            window.localStorage.removeItem('audi_sb_access_token');
            window.localStorage.removeItem('audi_sb_provider_token');
            try {
              await supabaseClient.auth.signOut();
            } catch (_) {}
            setUser(null);
            setPage('LOGIN');
            return;
          }
          setUser(data.user);
          setPage('DASHBOARD');
        } else {
          setPage('LOGIN');
        }
      } catch (err) {
        setPage('LOGIN');
      }
    };
    queryActiveSessionOnBoot();

    return () => {
      subscription.unsubscribe();
    };
  }, [supabaseClient]);

  const handleLoginSuccess = (loggedInUser: GitHubUser) => {
    setUser(loggedInUser);
    setPage('DASHBOARD');
  };

  const handleLogout = async () => {
    // Clear sandbox cookies as well
    document.cookie = 'audi_sandbox=; path=/; expires=Thu, 01 Jan 1970 00:00:01 GMT;';
    
    window.localStorage.removeItem('audi_sb_access_token');
    window.localStorage.removeItem('audi_sb_provider_token');

    if (supabaseClient) {
      try {
        await supabaseClient.auth.signOut();
      } catch (err) {
        console.error('Supabase signOut error:', err);
      }
    }

    try {
      await apiFetch('/api/auth/logout', { method: 'POST' });
    } catch (_) {
      // Ignore
    }

    setUser(null);
    setPage('LOGIN');
  };

  return (
    <div className="min-h-screen bg-transparent flex flex-col relative text-[#E6EDF3] bg-[#0d1117] selection:bg-[#00FF88]/30 selection:text-white">
      
      {/* Universal Top Nav Indicator with glowing status */}
      <nav className="border-b border-white/[0.04] h-16 flex items-center justify-between px-6 bg-[#05070a]/40 backdrop-blur-xl sticky top-0 z-40 w-full font-sans">
        <div className="max-w-7xl mx-auto w-full flex items-center justify-between">
          <div 
            onClick={() => { if (user) setPage('DASHBOARD'); }}
            className="flex items-center gap-3 cursor-pointer selection:bg-transparent"
          >
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-[#00FF88] via-[#00F0FF] to-[#00E575] p-[1.5px] shadow-[0_0_20px_rgba(0,255,136,0.22)] flex items-center justify-center transition-all duration-300 hover:scale-105">
              <div className="w-full h-full bg-[#05070a]/90 rounded-[10px] flex items-center justify-center">
                <svg viewBox="0 0 24 24" fill="none" className="w-[20px] h-[20px]" stroke="currentColor" strokeWidth={2.5}>
                  <path d="M16 18l6-6-6-6M8 6l-6 6 6 6" stroke="#00FF88" strokeLinecap="round" strokeLinejoin="round" />
                  <path d="M12 2v20" stroke="#00F0FF" strokeLinecap="round" />
                  <circle cx="12" cy="12" r="3" fill="#00FF88" className="animate-pulse" />
                </svg>
              </div>
            </div>
            <span className="font-extrabold text-xl md:text-2xl text-white tracking-[0.02em]">
              Audi<span className="text-[#00FF88]">Code</span>
            </span>
          </div>

          <div className="flex items-center gap-2.5 px-3 py-1 rounded-full bg-white/[0.02] border border-white/[0.04]">
            <span className="w-1.5 h-1.5 rounded-full bg-[#00FF88] shadow-[0_0_8px_#00FF88]"></span>
            <span className="font-mono text-[9px] text-[#8B949E] uppercase tracking-widest font-semibold">Active Session</span>
          </div>
        </div>
      </nav>

      {/* Main Core Router Panels */}
      <main className="flex-1 flex flex-col justify-start py-4">
        {page === 'INITIAL_CHECK' && (
          <div className="flex-1 flex flex-col items-center justify-center min-h-[60vh]">
            <RefreshCw className="animate-spin text-[#00FF88]" size={28} />
            <span className="font-mono text-xs text-[#7D8590] mt-3">// Resolving credential payloads...</span>
          </div>
        )}

        {page === 'LOGIN' && (
          <LoginView onLoginSuccess={handleLoginSuccess} />
        )}

        {page === 'DASHBOARD' && user && (
          <DashboardView
            user={user}
            onLogout={handleLogout}
          />
        )}
      </main>

      {/* Footer copyright indicators */}
      <footer className="border-t border-[#21262D]/40 py-6 text-center text-[10px] text-[#8B949E] font-sans">
        <div className="font-bold uppercase tracking-wider text-[#C9D1D9]">AudiCode Shell</div>
        <div className="text-[#484F58] mt-1 font-mono text-[9px]">
          SESSION ESTABLISHED {new Date().toLocaleDateString(undefined, { year: 'numeric', month: 'long', day: 'numeric' }).toUpperCase()}
        </div>
      </footer>
    </div>
  );
}
