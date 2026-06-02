import React, { useState, useEffect } from 'react';
import { LogOut, ShieldCheck, Terminal, Shield, Activity, Cpu, Layers, Lock, Sparkles, Search, Globe, ExternalLink, RefreshCw, FolderGit2, CheckCircle2 } from 'lucide-react';
import { Repository } from '../types';
import { apiFetch } from '../utils/api';

interface DashboardViewProps {
  user: { login: string; name: string | null; avatarUrl: string };
  onLogout: () => void;
}

export function DashboardView({ user, onLogout }: DashboardViewProps) {
  const [repos, setRepos] = useState<Repository[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedRepoId, setSelectedRepoId] = useState<string | null>(null);

  const fetchRepos = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await apiFetch('/api/repos');
      if (!res.ok) {
        throw new Error(`Failed to load repositories: ${res.statusText}`);
      }
      const data = await res.json();
      setRepos(data.repositories || []);
    } catch (err: any) {
      console.error('[DASHBOARD] error loading repos:', err);
      setError(err.message || 'An error occurred fetching repositories.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchRepos();
  }, []);

  const filteredRepos = repos.filter(repo => 
    repo.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
    (repo.description && repo.description.toLowerCase().includes(searchQuery.toLowerCase()))
  );

  const selectedRepo = repos.find(r => r.id === selectedRepoId);

  return (
    <div className="w-full max-w-5xl mx-auto py-6 px-4 md:px-6 animate-fade-in font-sans text-neutral-200">
      
      {/* Premium Header Row */}
      <header className="flex flex-col sm:flex-row justify-between items-start sm:items-center border-b border-white/[0.04] pb-6 mb-8 gap-4">
        <div className="flex items-center gap-4">
          <div className="relative">
            <img 
              src={user.avatarUrl} 
              alt="avatar" 
              className="w-[48px] h-[48px] rounded-xl border border-white/[0.08] shadow-[0_4px_16px_rgba(0,0,0,0.4)] hover:scale-105 transition-all duration-300" 
              referrerPolicy="no-referrer" 
            />
            <div className="absolute -bottom-1 -right-1 w-3.5 h-3.5 rounded-full bg-[#00FF88] border-2 border-[#0d1117] shadow-[0_0_8px_#00FF88]"></div>
          </div>
          <div>
            <h3 className="text-base font-black text-white tracking-wider uppercase">{user.name || user.login}</h3>
            <p className="text-[11px] text-[#00FF88] font-bold uppercase tracking-wider font-mono flex items-center gap-1.5 mt-0.5">
              <span>// SECURITY ROLE: CHIEF CODE AUDITOR</span>
              <span>·</span>
              <span className="text-[#8B949E]">@{user.login}</span>
            </p>
          </div>
        </div>

        <button
          onClick={onLogout}
          className="flex items-center gap-2 px-4 py-2 bg-white/[0.01] border border-white/[0.06] hover:bg-red-500/[0.05] hover:text-red-400 hover:border-red-500/30 rounded-xl font-bold text-[10px] uppercase tracking-widest text-[#8B949E] cursor-pointer transition-all duration-300 shadow-sm"
        >
          <LogOut size={12} strokeWidth={2.5} />
          Disengage
        </button>
      </header>

      {/* Main Grid: Info Cards */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
        
        {/* Profile Card */}
        <div className="glass-card rounded-2xl p-6 border border-white/[0.03] bg-white/[0.01] shadow-2xl relative overflow-hidden group">
          <div className="absolute top-0 right-0 p-8 opacity-[0.02] pointer-events-none text-[#00FF88] group-hover:scale-110 transition-transform duration-500">
            <ShieldCheck size={120} />
          </div>
          <p className="text-[10px] text-[#00FF88] uppercase tracking-[0.2em] font-extrabold mb-2 font-mono">// SESSION ASSURANCE</p>
          <h2 className="text-lg font-black text-white uppercase tracking-wider mb-4">Secure Profile</h2>
          
          <div className="space-y-3.5 text-xs text-[#8B949E]">
            <div className="flex justify-between items-center py-1.5 border-b border-white/[0.02]">
              <span className="font-medium text-neutral-400">Account Identity</span>
              <span className="font-mono text-white">#{user.login || 'guest'}</span>
            </div>
            <div className="flex justify-between items-center py-1.5 border-b border-white/[0.02]">
              <span className="font-medium text-neutral-400">Authority Issuer</span>
              <span className="font-mono text-[#00FF88] flex items-center gap-1 text-[11px] font-bold">
                <Lock size={10} />
                OAuth Verified
              </span>
            </div>
            <div className="flex justify-between items-center py-1.5 border-b border-white/[0.02]">
              <span className="font-medium text-neutral-400">Environment</span>
              <span className="font-mono text-neutral-300">Google Cloud Sandbox</span>
            </div>
            <div className="flex justify-between items-center py-1.5">
              <span className="font-medium text-neutral-400">Telemetry Status</span>
              <span className="font-mono text-[#00FF88] font-bold">READY</span>
            </div>
          </div>
        </div>

        {/* Engine Credentials Status */}
        <div className="glass-card rounded-2xl p-6 border border-white/[0.03] bg-white/[0.01] shadow-2xl relative overflow-hidden group">
          <div className="absolute top-0 right-0 p-8 opacity-[0.02] pointer-events-none text-[#00FFFF] group-hover:scale-110 transition-transform duration-500">
            <Cpu size={120} />
          </div>
          <p className="text-[10px] text-[#00FFFF] uppercase tracking-[0.2em] font-extrabold mb-2 font-mono">// SYSTEMS HARDENING</p>
          <h2 className="text-lg font-black text-white uppercase tracking-wider mb-4">Pipeline Metrics</h2>
          
          <div className="space-y-3.5 text-xs text-[#8B949E]">
            <div className="flex justify-between items-center py-1.5 border-b border-white/[0.02]">
              <span className="font-medium text-neutral-400">Taint Propagation Core</span>
              <span className="font-mono text-[#00FF88] font-bold">Active</span>
            </div>
            <div className="flex justify-between items-center py-1.5 border-b border-white/[0.02]">
              <span className="font-medium text-neutral-400">Compliance Standard</span>
              <span className="font-mono text-neutral-300">CWE / OWASP Top 10</span>
            </div>
            <div className="flex justify-between items-center py-1.5 border-b border-white/[0.02]">
              <span className="font-medium text-neutral-400">Active Repositories</span>
              <span className="font-mono text-[#00FF88] font-bold">{repos.length} Ingested</span>
            </div>
            <div className="flex justify-between items-center py-1.5">
              <span className="font-medium text-neutral-400">Authentication Link</span>
              <span className="font-mono text-neutral-100 font-bold uppercase text-[10px]">SUPABASE LIVE</span>
            </div>
          </div>
        </div>

        {/* Operations Center */}
        <div className="glass-card rounded-2xl p-6 border border-white/[0.03] bg-white/[0.01] shadow-2xl relative overflow-hidden group">
          <div className="absolute top-0 right-0 p-8 opacity-[0.02] pointer-events-none text-[#FFD700] group-hover:scale-110 transition-transform duration-500">
            <Layers size={120} />
          </div>
          <p className="text-[10px] text-[#FFD700] uppercase tracking-[0.2em] font-extrabold mb-2 font-mono">// OPERATING COMPONENT</p>
          <h2 className="text-lg font-black text-white uppercase tracking-wider mb-4">Command Terminal</h2>
          
          <div className="space-y-3 text-xs text-[#8B949E]">
            <div className="p-3 bg-white/[0.01] border border-white/[0.03] rounded-xl flex items-start gap-2.5">
              <Sparkles size={14} className="text-[#00FF88] mt-0.5 flex-shrink-0" />
              <div>
                <span className="block text-white font-bold text-[11px] uppercase">Active Targeting Terminal</span>
                {selectedRepo ? (
                  <span className="block text-[10px] mt-0.5 text-[#00FF88] font-mono leading-relaxed truncate">
                    TARGET: {selectedRepo.owner}/{selectedRepo.name}
                  </span>
                ) : (
                  <span className="block text-[10px] mt-0.5 leading-relaxed">No repository selected. Click a card in the integrated source manager to configure.</span>
                )}
              </div>
            </div>
            <div className="p-2.5 bg-neutral-900/60 border border-white/[0.02] rounded-lg font-mono text-[10px] text-[#00FF88] truncate">
              $ ref: {selectedRepo ? selectedRepo.defaultBranch : 'unconfigured_scope'}
            </div>
          </div>
        </div>

      </div>

      {/* NEW: Integrated Source Repositories Panel */}
      <section className="glass-card rounded-2xl p-6 border border-white/[0.03] bg-white/[0.01] shadow-2xl mb-8">
        <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center border-b border-white/[0.04] pb-4 mb-6 gap-4">
          <div>
            <p className="text-[10px] text-[#00FF88] uppercase tracking-[0.2em] font-extrabold mb-1 font-mono">// DATA LINK INTEGRATOR</p>
            <h2 className="text-xl font-black text-white uppercase tracking-wider">GitHub Source Repositories</h2>
          </div>
          <button 
            type="button"
            onClick={fetchRepos}
            disabled={loading}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white/[0.02] border border-white/[0.06] hover:bg-white/[0.06] text-neutral-300 hover:text-white text-[10px] uppercase font-bold tracking-wider cursor-pointer transition-all disabled:opacity-40"
          >
            <RefreshCw size={11} className={loading ? 'animate-spin' : ''} />
            Refetch Source
          </button>
        </div>

        {/* Searching Interface */}
        <div className="relative mb-6">
          <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 text-neutral-500" size={16} />
          <input 
            type="text"
            placeholder="Search matching git files and tree entities..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-neutral-900/60 border border-white/[0.04] focus:border-[#00FF88]/40 focus:ring-0 rounded-xl px-4 py-3 pl-11 text-xs text-white placeholder-neutral-500 outline-none transition-all"
          />
        </div>

        {/* Repos Cards Display Container */}
        {loading ? (
          <div className="flex flex-col items-center justify-center py-16 space-y-3">
            <RefreshCw className="animate-spin text-[#00FF88]" size={24} />
            <span className="font-mono text-xs text-[#8B949E]">// Requesting GitHub repository ledger...</span>
          </div>
        ) : error ? (
          <div className="border border-red-500/20 bg-red-500/[0.02] rounded-xl p-6 text-center">
            <p className="text-xs text-red-400 font-mono mb-3">{error}</p>
            <button 
              onClick={fetchRepos}
              className="px-4 py-2 bg-red-400/10 hover:bg-red-400/20 text-red-300 border border-red-400/20 text-[10px] uppercase font-black tracking-widest rounded-lg cursor-pointer transition-all"
            >
              Retry Connection
            </button>
          </div>
        ) : filteredRepos.length === 0 ? (
          <div className="border border-white/[0.02] bg-[#0d1117]/30 rounded-xl p-12 text-center">
            <FolderGit2 className="mx-auto mb-3 text-neutral-600" size={32} />
            <p className="text-xs text-[#8B949E]">
              {searchQuery ? 'No repositories found matching current query.' : 'No repositories returned from GitHub.'}
            </p>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {filteredRepos.map((repo) => {
              const isSelected = repo.id === selectedRepoId;
              return (
                <div 
                  key={repo.id}
                  onClick={() => setSelectedRepoId(repo.id)}
                  className={`relative rounded-xl p-5 border cursor-pointer transition-all duration-300 select-none group flex flex-col justify-between min-h-[140px] ${
                    isSelected 
                      ? 'bg-[#00FF88]/[0.02] border-[#00FF88] shadow-[0_0_15px_rgba(0,255,136,0.06)]' 
                      : 'bg-white/[0.01] border-white/[0.03] hover:border-white/[0.08] hover:bg-white/[0.02] hover:shadow-lg'
                  }`}
                >
                  <div>
                    {/* Header: Name and Private/Public */}
                    <div className="flex items-start justify-between gap-2.5 mb-2.5">
                      <div className="flex items-center gap-2 overflow-hidden">
                        <FolderGit2 className={isSelected ? 'text-[#00FF88]' : 'text-neutral-400 group-hover:text-neutral-200 transition-colors'} size={15} />
                        <h4 className="font-extrabold text-xs text-white truncate uppercase tracking-wider group-hover:text-[#00FF88] transition-colors">
                          {repo.name}
                        </h4>
                      </div>
                      
                      {repo.isPrivate ? (
                        <div className="flex-shrink-0 flex items-center gap-1 text-[9px] px-1.5 py-0.5 rounded bg-neutral-800/80 text-neutral-400 font-mono uppercase font-bold border border-white/[0.02]">
                          <Lock size={8} />
                          Private
                        </div>
                      ) : (
                        <div className="flex-shrink-0 flex items-center gap-1 text-[9px] px-1.5 py-0.5 rounded bg-[#00FF88]/10 text-[#00FF88] font-mono uppercase font-bold border border-[#00FF88]/10">
                          <Globe size={8} />
                          Public
                        </div>
                      )}
                    </div>

                    <p className="text-xs text-[#8B949E] line-clamp-2 leading-relaxed mb-4">
                      {repo.description}
                    </p>
                  </div>

                  {/* Footer metadata row */}
                  <div className="flex items-center justify-between border-t border-white/[0.03] pt-3 mt-auto">
                    <span className="font-mono text-[10px] text-neutral-500 uppercase">
                      Branch: <span className="text-neutral-300 font-bold">{repo.defaultBranch}</span>
                    </span>

                    <div className="flex items-center gap-2">
                      <a 
                        href={repo.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        onClick={(e) => e.stopPropagation()}
                        className="p-1 text-neutral-500 hover:text-white transition-colors"
                        title="View on GitHub"
                      >
                        <ExternalLink size={12} />
                      </a>
                      
                      {isSelected && (
                        <span className="text-[#00FF88] flex items-center gap-1 font-mono text-[9px] font-bold uppercase">
                          <CheckCircle2 size={11} />
                          Selected
                        </span>
                      )}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </section>

      {/* Hero Visual Section: Static Environment Matrix */}
      <section className="glass-card rounded-2xl p-6 border border-white/[0.03] bg-white/[0.01] shadow-3xl relative overflow-hidden">
        <div className="absolute top-0 right-0 p-6 opacity-[0.01] pointer-events-none text-white">
          <Terminal size={140} />
        </div>
        
        <p className="text-[10px] text-[#00FF88] uppercase tracking-[0.2em] font-extrabold mb-2 font-mono">// PLATFORM ASSURANCE OVERVIEW</p>
        <h2 className="text-xl font-black text-white uppercase tracking-wider mb-3 flex items-center gap-2">
          <Activity size={18} className="text-[#00FF88] animate-pulse" />
          Secure Shell Active
        </h2>
        
        <p className="text-xs text-[#8B949E] max-w-2xl leading-relaxed mb-6">
          Your credentials and identity are fully initialized inside the premium developer sandbox. Scanning systems, AST compilations, taint propagation channels, rules matrices, and historic database integrations have been parsed, validated, and hardened.
        </p>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 border-t border-white/[0.04] pt-6 font-mono text-center">
          <div className="bg-[#03060a]/40 border border-white/[0.03] rounded-xl p-4">
            <span className="block text-[#00FFFF] font-bold text-base mb-1 uppercase">ZERO TRUST</span>
            <span className="block text-[9px] text-[#8B949E] uppercase font-bold tracking-widest">AUTHENTICATION SCRIPT</span>
          </div>
          <div className="bg-[#03060a]/40 border border-white/[0.03] rounded-xl p-4">
            <span className="block text-[#00FF88] font-bold text-base mb-1 uppercase">HMAC VERIFY</span>
            <span className="block text-[9px] text-[#8B949E] uppercase font-bold tracking-widest">DECRYPT & RESOLVE</span>
          </div>
          <div className="bg-[#03060a]/40 border border-white/[0.03] rounded-xl p-4">
            <span className="block text-[#FFD700] font-bold text-base mb-1 uppercase">SANDBOX BYPASS</span>
            <span className="block text-[9px] text-[#8B949E] uppercase font-bold tracking-widest">SESSION CONDUITS</span>
          </div>
        </div>
      </section>

    </div>
  );
}
