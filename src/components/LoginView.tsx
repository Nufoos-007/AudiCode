import React, { useState, useEffect } from 'react';
import { Shield, Github, Zap, Terminal, Key } from 'lucide-react';
import { getSupabase } from '../supabase';

interface LoginViewProps {
  onLoginSuccess: (user: any) => void;
}

export function LoginView({ onLoginSuccess }: LoginViewProps) {
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [githubPat, setGithubPat] = useState<string>('');
  const [showPatInput, setShowPatInput] = useState<boolean>(false);

  const handleSandboxLogin = async () => {
    setError(null);
    setLoading(true);
    try {
      const sandboxUser = {
        id: 'guest-dev',
        login: 'demo-auditor',
        name: 'Sandbox Auditor',
        avatarUrl: 'data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><circle cx="50" cy="50" r="50" fill="%231f242c"/><path d="M50,85 C25,85 15,67 15,60 C15,53 25,43 50,43 C75,43 85,53 85,60 C85,67 75,85 50,85 Z" fill="%238b949e"/><circle cx="50" cy="27" r="14" fill="%238b949e"/></svg>',
        accessToken: 'demo_token_sandbox_bypass_true',
        isSandbox: true
      };
      
      // Store session details in localStorage
      window.localStorage.setItem('audi_sb_access_token', 'demo_token_sandbox_bypass_true');
      window.localStorage.setItem('audi_sb_user_session', JSON.stringify(sandboxUser));
      
      onLoginSuccess(sandboxUser);
    } catch (err: any) {
      setError(err.message || 'Demo access failed.');
    } finally {
      setLoading(false);
    }
  };

  const handlePatLoginSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!githubPat.trim()) {
      setError('Please provide a valid GitHub Personal Access Token.');
      return;
    }

    setError(null);
    setLoading(true);
    const token = githubPat.trim();

    try {
      // Validate the token against public GitHub API
      const response = await fetch('https://api.github.com/user', {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Accept': 'application/vnd.github.v3+json',
        }
      });

      if (!response.ok) {
        throw new Error(`GitHub token validation failed (Status: ${response.status}). Please verify token scopes.`);
      }

      const rawUser = await response.json();
      const authenticatedUser = {
        id: String(rawUser.id),
        login: rawUser.login,
        name: rawUser.name || rawUser.login,
        avatarUrl: rawUser.avatar_url,
        accessToken: token,
        isSandbox: false
      };

      // Store in localStorage for persistence
      window.localStorage.setItem('audi_sb_access_token', token);
      window.localStorage.setItem('audi_sb_provider_token', token);
      window.localStorage.setItem('audi_sb_user_session', JSON.stringify(authenticatedUser));

      onLoginSuccess(authenticatedUser);
    } catch (err: any) {
      setError(err.message || 'GitHub PAT login failed. Please ensure the token is active and has "repo" scope read permissions.');
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
        {/* Sleek Active State Indicator Badge */}
        <div className="inline-flex items-center gap-2.5 px-5.5 py-2 mb-10 rounded-xl border border-[#00FF88]/20 bg-[#00FF88]/[0.03] font-condensed text-[11px] tracking-[0.25em] text-[#00FF88] uppercase font-bold shadow-[0_0_25px_rgba(0,255,136,0.05)]">
          <span className="w-1.5 h-1.5 rounded-full bg-[#00FF88] shadow-[0_0_8px_#00FF88] animate-pulse"></span>
          Source-to-Sink Tracking Active
        </div>

        {/* Cinematic Headline with Cybernetic visual hierarchy */}
        <h1 className="mb-4 text-center flex flex-col items-center">
          <span className="font-display font-light text-lg md:text-xl text-[#8B949E] tracking-[0.1em] leading-none uppercase mt-3 mb-1">
            Analyze your vulnerabilities
          </span>
          <span className="font-display font-black text-6xl md:text-[84px] leading-none tracking-tight text-transparent bg-clip-text bg-gradient-to-r from-[#00FF88] via-[#00FFF0] to-[#00FF88] select-none mt-1 mb-4 filter drop-shadow-[0_0_25px_rgba(0,255,136,0.25)]">
            EXPOSED.
          </span>
        </h1>

        <p className="font-sans text-xs md:text-sm font-normal leading-relaxed text-[#8B949E] max-w-md mx-auto mb-10">
          Scan repositories directly in your browser. No separate server, zero configuration, fully secure.
        </p>

        {/* Authentication Options in Glassmorphic Panel */}
        <div className="glass-card rounded-2xl p-8 md:p-10 mb-10 shadow-[0_32px_100px_rgba(0,0,0,0.8)] text-left relative overflow-hidden border border-white/[0.03]">
          {/* Subtle inside card lighting highlight */}
          <div className="absolute -top-12 -left-12 w-40 h-40 bg-gradient-to-br from-[#00FF88]/[0.04] to-transparent rounded-full blur-2xl"></div>

          <div className="relative z-10 flex items-center gap-4 mb-6">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-[#00E575] via-[#00FF88] to-[#00E575] flex items-center justify-center text-black shadow-[0_0_20px_rgba(0,255,136,0.2)]">
              <Terminal size={20} strokeWidth={2.5} />
            </div>
            <div className="flex flex-col justify-center">
              <h2 className="font-display text-base font-bold tracking-wider text-white uppercase leading-none">Initialize workspace</h2>
              <p className="font-condensed text-[11px] text-[#8B949E] uppercase tracking-wider leading-none mt-1">Direct client-side execution. Zero server dependencies.</p>
            </div>
          </div>

          {error && (
            <div className="p-4 mb-6 rounded-xl bg-red-500/[0.04] border border-red-500/20 font-mono text-xs text-red-400">
              ⚠️ {error}
            </div>
          )}

          <div className="relative z-10 flex flex-col gap-4">
            
            {/* Main Sandbox auditor button (extremely quick startup) */}
            <button
              id="btn-sandbox-bypass"
              onClick={handleSandboxLogin}
              disabled={loading}
              className="flex items-center justify-center gap-3 w-full py-4 px-6 rounded-xl bg-gradient-to-r from-[#00FF88] to-[#00E575] text-black hover:shadow-[0_0_25px_rgba(0,255,136,0.3)] font-display font-extrabold text-xs uppercase tracking-[0.15em] cursor-pointer transition-all duration-300 disabled:opacity-50 hover:scale-[1.01] active:scale-[0.99]"
            >
              <Zap size={14} className="text-black fill-black" />
              {loading ? 'Booting Sandbox Environment...' : 'Use Sandbox Auditor (Preloaded Repos)'}
            </button>

            <div className="flex items-center my-2 select-none">
              <div className="flex-1 border-t border-white/[0.04]"></div>
              <span className="px-3 font-mono text-[9px] text-[#484F58] uppercase tracking-widest font-bold">OR INTEGRATE PERSONAL ACCOUNT</span>
              <div className="flex-1 border-t border-white/[0.04]"></div>
            </div>

            {/* Toggle PAT input form */}
            {!showPatInput ? (
              <button
                type="button"
                onClick={() => setShowPatInput(true)}
                className="flex items-center justify-center gap-3 w-full py-4 px-6 rounded-xl bg-white/[0.01] border border-white/[0.05] text-white hover:bg-white/[0.03] hover:border-white/[0.12] font-display font-bold text-xs uppercase tracking-[0.15em] cursor-pointer transition-all duration-300"
              >
                <Key size={14} className="text-[#00FFFF]" />
                Authenticate with GitHub PAT Info
              </button>
            ) : (
              <form onSubmit={handlePatLoginSubmit} className="space-y-4 animate-slide-down">
                <div>
                  <label className="block font-display text-[10px] text-[#8B949E] uppercase tracking-widest font-black mb-1.5">
                    GitHub Personal Access Token (PAT)
                  </label>
                  <div className="relative">
                    <input
                      type="password"
                      value={githubPat}
                      onChange={(e) => setGithubPat(e.target.value)}
                      placeholder="ghp_..."
                      className="w-full bg-[#05070a]/90 text-[#E6EDF3] border border-white/[0.08] hover:border-white/[0.15] focus:border-[#00FF88] rounded-xl px-4 py-3 text-xs font-mono placeholder-[#484F58] focus:outline-none transition-all"
                    />
                  </div>
                  <p className="font-sans text-[10px] text-[#8B949E] leading-relaxed mt-2">
                    Enter a token with <code>repo</code> scope permission to read catalogs and trees natively. Your token is processed exclusively on your browser and is never transmitted out.
                  </p>
                </div>

                <div className="flex gap-3 pt-2">
                  <button
                    type="button"
                    onClick={() => setShowPatInput(false)}
                    disabled={loading}
                    className="px-4 py-3 rounded-xl bg-white/[0.01] border border-white/[0.05] hover:bg-white/[0.03] text-white font-display text-[10px] uppercase font-black tracking-widest cursor-pointer transition-all"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    disabled={loading}
                    className="flex-1 py-3 px-5 rounded-xl bg-gradient-to-r from-[#00FFFF] to-[#3A4DF3] text-white hover:shadow-[0_0_20px_rgba(0,255,255,0.2)] font-display font-black text-[10px] uppercase tracking-widest cursor-pointer hover:scale-[1.01] active:scale-[0.99] transition-all"
                  >
                    {loading ? 'Authenticating...' : 'Validate and Connect Token'}
                  </button>
                </div>
              </form>
            )}

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
            <span className="block text-base md:text-lg font-display font-black text-[#00FFFF] tracking-wide mb-1 uppercase">CLIENT SIDE</span>
            <span className="font-condensed font-bold text-[10px] tracking-widest text-[#8B949E] uppercase">UNIVERSAL SCANNER</span>
          </div>
        </div>
      </div>
    </div>
  );
}
