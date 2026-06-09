import React, { useState, useEffect } from 'react';
import { Shield, Github, Zap, Terminal } from 'lucide-react';
import { getSupabase } from '../supabase';

interface LoginViewProps {
  onLoginSuccess: (user: any) => void;
}

export function LoginView({ onLoginSuccess }: LoginViewProps) {
  const [hasConfig, setHasConfig] = useState<boolean>(false);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [missingVars, setMissingVars] = useState<string[]>([]);

  useEffect(() => {
    // Fetch live configurations and missing environment variable checklists
    fetch('/api/auth/diagnostics')
      .then(res => res.json())
      .then(data => {
        setHasConfig(data.supabase.urlConfigured && data.supabase.anonKeyConfigured);
        setMissingVars(data.missingEnvVars || []);
      })
      .catch(err => {
        console.error('Error reading backend diagnostics parameters:', err);
        // Fallback to legacy config if diagnostics endpoint fails (failsafe)
        fetch('/api/config')
          .then(res => res.json())
          .then(data1 => {
            setHasConfig(!!(data1.supabaseUrl && data1.supabaseAnonKey));
          })
          .catch(e => console.error(e));
      });
  }, []);

  const handleGitHubConnect = async () => {
    setError(null);
    setLoading(true);
    try {
      const supabase = await getSupabase();
      const { error: err } = await supabase.auth.signInWithOAuth({
        provider: 'github',
        options: {
          redirectTo: 'https://audicode-sigma.vercel.app',
          scopes: 'repo read:user'
        }
      });
      if (err) throw err;
    } catch (err: any) {
      setError(err.message || 'Connecting with GitHub failed.');
      setLoading(false);
    }
  };

  const handleSandboxLogin = async () => {
    setError(null);
    setLoading(true);
    try {
      const res = await fetch('/api/auth/sandbox', { method: 'POST' });
      if (!res.ok) throw new Error('Enabling sandbox demo environment failed.');
      const data = await res.json();
      window.localStorage.setItem('audi_sb_access_token', 'demo_token_sandbox_bypass_true');
      onLoginSuccess(data.user);
    } catch (err: any) {
      setError(err.message || 'Demo access failed.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div id="login-container" className="relative min-h-[90vh] flex flex-col justify-center items-center py-16 px-6 overflow-hidden">
      
      {/* Cinematic Ambient Lighting - Top glow & moving secondary flare */}
      <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[700px] h-[350px] bg-gradient-to-b from-[#00FF88]/[0.08] to-transparent rounded-full blur-[100px] pointer-events-none z-0 animate-breathe"></div>
      <div className="absolute bottom-1/4 left-1/3 w-[300px] h-[300px] bg-gradient-to-tr from-[#3A4DF3]/[0.03] to-transparent rounded-full blur-[80px] pointer-events-none z-0"></div>

      <div className="relative z-10 w-full max-w-2xl text-center animate-fade-in">


        {/* Cinematic Headline with Cybernetic visual hierarchy */}
        <h1 className="mb-8 text-center flex flex-col items-center">
          <span className="font-display font-light text-lg md:text-xl text-[#8B949E] tracking-[0.1em] leading-none uppercase mt-3 mb-1">
            Your vibe-coded apps
          </span>
          <span className="font-display font-black text-6xl md:text-[98px] leading-none tracking-tight text-transparent bg-clip-text bg-gradient-to-r from-[#00FF88] via-[#00FFF0] to-[#00FF88] select-none mt-1 mb-4 filter drop-shadow-[0_0_25px_rgba(0,255,136,0.25)] animate-pulse">
            EXPOSED.
          </span>
        </h1>

        <p className="font-sans text-xs md:text-sm font-normal leading-relaxed text-[#8B949E] max-w-md mx-auto mb-12">
          Analyze public and private GitHub repositories in time.
        </p>

        {/* Authentication Options in Glassmorphic Panel */}
        <div className="glass-card rounded-2xl p-8 md:p-10 mb-10 shadow-[0_32px_100px_rgba(0,0,0,0.8)] text-left relative overflow-hidden border border-white/[0.03]">
          {/* Subtle inside card lighting highlight */}
          <div className="absolute -top-12 -left-12 w-40 h-40 bg-gradient-to-br from-[#00FF88]/[0.04] to-transparent rounded-full blur-2xl"></div>

          <div className="relative z-10 flex items-center gap-4 mb-8">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-[#00E575] via-[#00FF88] to-[#00E575] flex items-center justify-center text-black shadow-[0_0_20px_rgba(0,255,136,0.2)]">
              <Terminal size={20} strokeWidth={2.5} />
            </div>
            <div className="flex flex-col justify-center">
              <h2 className="font-display text-base font-bold tracking-wider text-white uppercase leading-none">Initialize workspace</h2>
              <p className="font-condensed text-[11px] text-[#8B949E] uppercase tracking-wider leading-none mt-1">Direct authorization channel. No registration required.</p>
            </div>
          </div>

          {error && (
            <div className="p-4 mb-6 rounded-xl bg-red-500/[0.04] border border-red-500/20 font-mono text-xs text-red-400">
              ⚠️ {error}
            </div>
          )}

          <div className="relative z-10 flex flex-col gap-4">
            {hasConfig ? (
              <button
                id="btn-github-oauth"
                onClick={handleGitHubConnect}
                disabled={loading}
                className="flex items-center justify-center gap-3 w-full py-4 px-6 rounded-xl bg-gradient-to-r from-[#00FF88] to-[#00E575] text-black hover:shadow-[0_0_25px_rgba(0,255,136,0.3)] font-display font-extrabold text-xs uppercase tracking-[0.15em] cursor-pointer transition-all duration-300 disabled:opacity-50 hover:scale-[1.01] active:scale-[0.99]"
              >
                <Github size={16} strokeWidth={2.5} />
                {loading ? 'Routing OAuth parameters...' : 'Continue with GitHub'}
              </button>
            ) : (
              <div className="rounded-xl p-5 bg-red-500/[0.02] border border-red-500/15 font-sans text-xs text-[#8B949E] space-y-3 mb-2">
                <p className="flex items-center gap-2">
                  <span className="w-1.5 h-1.5 rounded-full bg-red-500 animate-pulse"></span>
                  <span className="font-display text-white font-bold text-xs uppercase tracking-wider">SUPABASE CONFIGURATION DISCOVERABILITY ERROR</span>
                </p>
                <p className="leading-relaxed text-[11px] text-[#8B949E]/80">To enable persistent team audits, collaborative history logs, and instant secure direct GitHub sign-ins, configure the following database variables:</p>
                
                <div className="flex flex-wrap gap-1.5 py-1">
                  {missingVars.map(v => (
                    <span key={v} className="px-2 py-0.5 rounded-md bg-red-500/[0.06] border border-red-500/20 font-mono font-bold text-[#FF8888] text-[9px] uppercase tracking-wider">
                      {v}
                    </span>
                  ))}
                </div>

                <div className="border-t border-white/[0.04] pt-2 mt-2">
                  <p className="text-[10px] text-[#484F58] font-mono">// Configure Supabase credentials in your .env or platform secrets panel.</p>
                </div>
              </div>
            )}

            <button
              id="btn-sandbox-bypass"
              onClick={handleSandboxLogin}
              disabled={loading}
              className="flex items-center justify-center gap-3 w-full py-4 px-6 rounded-xl bg-white/[0.01] border border-white/[0.05] text-white hover:bg-white/[0.03] hover:border-white/[0.12] hover:shadow-[0_0_30px_rgba(255,215,0,0.05)] font-display font-bold text-xs uppercase tracking-[0.15em] cursor-pointer transition-all duration-300 disabled:opacity-50 hover:scale-[1.01] active:scale-[0.99]"
            >
              <Zap size={14} className="text-[#FFD700]" />
              {loading ? 'Booting sandbox...' : 'Use Sandbox Auditor Bypass'}
            </button>
          </div>
        </div>

        {/* Feature quick stats */}
        <div className="grid grid-cols-3 gap-4 max-w-xl mx-auto font-condensed text-xs text-[#8B949E] border-t border-white/[0.04] pt-10 mt-6 tracking-wider">
          <div className="text-center">
            <span className="block text-base md:text-lg font-display font-black text-[#00FFFF] tracking-wide mb-1 uppercase">0ms INGESTION</span>
            <span className="font-condensed font-bold text-[10px] tracking-widest text-[#8B949E] uppercase">REAL-TIME PIPELINE</span>
          </div>
          <div className="text-center border-x border-white/[0.04] px-2">
            <span className="block text-base md:text-lg font-display font-black text-[#00FF88] tracking-wide mb-1 uppercase">AST ANALYSIS</span>
            <span className="font-condensed font-bold text-[10px] tracking-widest text-[#8B949E] uppercase">TAINT DATA FLOW</span>
          </div>
          <div className="text-center">
            <span className="block text-base md:text-lg font-display font-black text-[#00FFFF] tracking-wide mb-1 uppercase">MULTI-LANG</span>
            <span className="font-condensed font-bold text-[10px] tracking-widest text-[#8B949E] uppercase">UNIVERSAL SCANNER</span>
          </div>
        </div>
      </div>
    </div>
  );
}
