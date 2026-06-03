import React, { useState, useEffect } from 'react';
import { LogOut, ShieldCheck, Terminal, Shield, Activity, Cpu, Layers, Lock, Sparkles, Search, Globe, ExternalLink, RefreshCw, FolderGit2, CheckCircle2, FileCode, Download, Eye, FileText, Ban, Copy } from 'lucide-react';
import { Repository, Finding, ScanResult } from '../types';
import { apiFetch } from '../utils/api';
import { RuleRegistryView } from './RuleRegistryView';

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

  // TREE RETRIEVAL & TARGET METADATA STATES
  const [treeResult, setTreeResult] = useState<any | null>(null);
  const [treeLoading, setTreeLoading] = useState<boolean>(false);
  const [treeError, setTreeError] = useState<string | null>(null);
  const [showTreePanel, setShowTreePanel] = useState<boolean>(false);
  const [treeSearch, setTreeSearch] = useState<string>('');

  // RISK RANKING ENGINE STATES
  const [scanProfile, setScanProfile] = useState<'quick' | 'standard' | 'deep'>('standard');
  const [rankingResult, setRankingResult] = useState<any | null>(null);
  const [rankingLoading, setRankingLoading] = useState<boolean>(false);
  const [rankingError, setRankingError] = useState<string | null>(null);
  const [rankingSearch, setRankingSearch] = useState<string>('');

  // CONTENT FETCHING LAYER STATES
  const [fetchedContentResult, setFetchedContentResult] = useState<any | null>(null);
  const [fetchingContent, setFetchingContent] = useState<boolean>(false);
  const [fetchingContentError, setFetchingContentError] = useState<string | null>(null);
  const [selectedFileForPreview, setSelectedFileForPreview] = useState<any | null>(null);

  // DETERMINISTIC SCAN ENGINE STATES
  const [scanResult, setScanResult] = useState<any | null>(null);
  const [scanning, setScanning] = useState<boolean>(false);
  const [scanError, setScanError] = useState<string | null>(null);
  const [selectedFindingForDrilldown, setSelectedFindingForDrilldown] = useState<any | null>(null);
  const [copiedPromptId, setCopiedPromptId] = useState<string | null>(null);

  const handleCopyPromptPack = (findingId: string, promptText: string) => {
    navigator.clipboard.writeText(promptText)
      .then(() => {
        setCopiedPromptId(findingId);
        setTimeout(() => setCopiedPromptId(null), 2000);
      })
      .catch((err) => {
        console.error('Failed to copy prompt pack:', err);
      });
  };

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

  const fetchTree = async (repoItem: Repository) => {
    setTreeLoading(true);
    setTreeError(null);
    setTreeResult(null);
    setShowTreePanel(true);
    try {
      const res = await apiFetch(`/api/tree?owner=${encodeURIComponent(repoItem.owner)}&repo=${encodeURIComponent(repoItem.name)}&branch=${encodeURIComponent(repoItem.defaultBranch)}`);
      if (!res.ok) {
        const errJson = await res.json().catch(() => ({}));
        throw new Error(errJson.error || `Failed to fetch directory tree: ${res.statusText}`);
      }
      const data = await res.json();
      setTreeResult(data);
    } catch (err: any) {
      console.error('[DASHBOARD] error fetching tree:', err);
      setTreeError(err.message || 'An error occurred fetching repository tree.');
    } finally {
      setTreeLoading(false);
    }
  };

  const runRiskRanking = async () => {
    const selected = repos.find(r => r.id === selectedRepoId);
    if (!selected) return;

    setRankingLoading(true);
    setRankingError(null);
    setRankingResult(null);

    try {
      const res = await apiFetch(`/api/rank?owner=${encodeURIComponent(selected.owner)}&repo=${encodeURIComponent(selected.name)}&branch=${encodeURIComponent(selected.defaultBranch)}&profile=${scanProfile}`);
      if (!res.ok) {
        const errJson = await res.json().catch(() => ({}));
        throw new Error(errJson.error || `Risk calculation failed: ${res.statusText}`);
      }
      const data = await res.json();
      setRankingResult(data);
    } catch (err: any) {
      console.error('[RANKING ENGINE] execution error:', err);
      setRankingError(err.message || 'An error occurred during risk engine prioritization execution.');
    } finally {
      setRankingLoading(false);
    }
  };

  const runContentFetch = async () => {
    const selected = repos.find(r => r.id === selectedRepoId);
    if (!selected || !rankingResult || !rankingResult.selectedEntries) return;

    setFetchingContent(true);
    setFetchingContentError(null);
    setFetchedContentResult(null);
    setSelectedFileForPreview(null);

    try {
      const res = await apiFetch('/api/fetch-content', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          owner: selected.owner,
          repo: selected.name,
          defaultBranch: selected.defaultBranch,
          profile: scanProfile,
          rankedEntries: rankingResult.selectedEntries
        })
      });

      if (!res.ok) {
        const errJson = await res.json().catch(() => ({}));
        throw new Error(errJson.error || `Content fetching failed: ${res.statusText}`);
      }

      const data = await res.json();
      setFetchedContentResult(data);
      if (data.files && data.files.length > 0) {
        setSelectedFileForPreview(data.files[0]);
      }
    } catch (err: any) {
      console.error('[CONTENT FETCH] execution error:', err);
      setFetchingContentError(err.message || 'An error occurred during Ranked Files Content Fetching phase.');
    } finally {
      setFetchingContent(false);
    }
  };

  const runDeterministicScan = async () => {
    if (!fetchedContentResult || !fetchedContentResult.files) return;

    setScanning(true);
    setScanError(null);
    setScanResult(null);
    setSelectedFindingForDrilldown(null);

    try {
      const res = await apiFetch('/api/scan', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          profile: scanProfile,
          files: fetchedContentResult.files
        })
      });

      if (!res.ok) {
        const errJson = await res.json().catch(() => ({}));
        throw new Error(errJson.error || `Scan failed: ${res.statusText}`);
      }

      const data = await res.json();
      setScanResult(data);
      if (data.findings && data.findings.length > 0) {
        setSelectedFindingForDrilldown(data.findings[0]);
      }
    } catch (err: any) {
      console.error('[DETERMINISTIC SCAN] execution error:', err);
      setScanError(err.message || 'An error occurred during Deterministic Scanning phase.');
    } finally {
      setScanning(false);
    }
  };

  useEffect(() => {
    fetchRepos();
  }, []);

  useEffect(() => {
    if (selectedRepoId) {
      const selected = repos.find(r => r.id === selectedRepoId);
      if (selected) {
        fetchTree(selected);
        setRankingResult(null);
        setRankingError(null);
        setFetchedContentResult(null);
        setFetchingContentError(null);
        setSelectedFileForPreview(null);
        setScanResult(null);
        setScanError(null);
        setSelectedFindingForDrilldown(null);
      }
    } else {
      setTreeResult(null);
      setTreeError(null);
      setShowTreePanel(false);
      setRankingResult(null);
      setRankingError(null);
      setFetchedContentResult(null);
      setFetchingContentError(null);
      setSelectedFileForPreview(null);
      setScanResult(null);
      setScanError(null);
      setSelectedFindingForDrilldown(null);
    }
  }, [selectedRepoId, repos]);

  const filteredRepos = repos.filter(repo => 
    repo.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
    (repo.description && repo.description.toLowerCase().includes(searchQuery.toLowerCase()))
  );

  const selectedRepo = repos.find(r => r.id === selectedRepoId);

  const filteredTreeEntries = treeResult
    ? treeResult.entries.filter((entry: any) =>
        entry.path.toLowerCase().includes(treeSearch.toLowerCase())
      )
    : [];

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

      {/* RISK RANKING ENGINE INTERACTIVE SECTION */}
      {selectedRepo && (
        <section className="glass-card rounded-2xl p-6 border border-white/[0.03] bg-white/[0.01] shadow-2xl mb-8 animate-fade-in">
          <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center border-b border-white/[0.04] pb-4 mb-6 gap-4">
            <div>
              <p className="text-[10px] text-[#00FF88] uppercase tracking-[0.2em] font-extrabold mb-1 font-mono">// THREAT CONSOLE ALPHA</p>
              <h2 className="text-xl font-black text-white uppercase tracking-wider flex items-center gap-2">
                <Shield className="text-[#00FF88]" size={20} />
                Risk Ranking Engine
              </h2>
            </div>
            <div className="flex items-center gap-2">
              <span className="px-3 py-1 bg-white/[0.02] border border-[#00FF88]/20 text-[10px] uppercase font-black text-[#00FF88] font-mono rounded-lg flex items-center gap-1.5">
                Target: {selectedRepo.owner}/{selectedRepo.name}
              </span>
            </div>
          </div>

          <p className="text-xs text-neutral-400 mb-6 leading-relaxed">
            Calculates vulnerability exposure likelihood by indexing project tree elements against known attack surface weight heuristics. Evaluated deterministically with zero content fetch latency.
          </p>

          {/* Profile Switcher & Trigger Button */}
          <div className="flex flex-col md:flex-row gap-4 items-center justify-between bg-[#03060a]/30 p-4 rounded-xl border border-white/[0.02] mb-6">
            <div className="flex flex-col sm:flex-row items-start sm:items-center gap-3 w-full md:w-auto">
              <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-neutral-400">// Select Scan Profile:</span>
              <div className="flex bg-neutral-950 p-1 rounded-lg border border-white/[0.06] w-full sm:w-auto">
                {(['quick', 'standard', 'deep'] as const).map((p) => (
                  <button
                    key={p}
                    type="button"
                    onClick={() => setScanProfile(p)}
                    className={`px-4 py-1.5 rounded-md text-[10px] font-bold uppercase tracking-wider transition-all cursor-pointer flex-1 sm:flex-initial text-center ${
                      scanProfile === p
                        ? 'bg-[#00FF88]/10 border border-[#00FF88]/30 text-[#00FF88]'
                        : 'text-neutral-500 hover:text-neutral-300'
                    }`}
                  >
                    {p}
                  </button>
                ))}
              </div>
            </div>

            <button
              onClick={runRiskRanking}
              disabled={rankingLoading}
              className="w-full md:w-auto px-5 py-2.5 bg-[#00FF88] hover:bg-[#00FF88]/95 disabled:bg-neutral-800 text-neutral-950 font-black text-[10px] uppercase tracking-widest rounded-xl transition-all cursor-pointer disabled:cursor-not-allowed flex items-center justify-center gap-2 shadow-[0_4px_20px_rgba(0,255,136,0.2)]"
            >
              {rankingLoading ? (
                <>
                  <RefreshCw className="animate-spin" size={13} />
                  Calculating Scores...
                </>
              ) : (
                <>
                  <Activity size={13} />
                  Calculate Risk Prioritization
                </>
              )}
            </button>
          </div>

          {rankingLoading ? (
            <div className="flex flex-col items-center justify-center py-20 space-y-4">
              <RefreshCw className="animate-spin text-[#00FF88]" size={32} />
              <div className="text-center">
                <span className="block font-mono text-xs text-[#00FF88] uppercase tracking-widest font-black animate-pulse">// RISK HEURISTICS PROPAGATION ACTIVE</span>
                <span className="block font-mono text-[10px] text-neutral-500 mt-1 uppercase">// Mapping patterns, weights, and directory hierarchies...</span>
              </div>
            </div>
          ) : rankingError ? (
            <div className="border border-red-500/20 bg-red-500/[0.02] rounded-xl p-6 text-center">
              <p className="text-xs text-red-100 font-mono mb-3">{rankingError}</p>
              <button 
                onClick={runRiskRanking}
                className="px-4 py-2 bg-red-400/10 hover:bg-red-400/20 text-red-300 border border-red-400/20 text-[10px] uppercase font-black tracking-widest rounded-lg cursor-pointer transition-all"
              >
                Retry Calculation
              </button>
            </div>
          ) : rankingResult ? (
            <div className="animate-fade-in text-neutral-300">
              
              {/* Stats Bento Grid */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
                <div className="bg-[#03060a]/40 border border-white/[0.02] rounded-xl p-4">
                  <span className="block text-[9px] text-neutral-500 uppercase font-mono tracking-wider font-bold">// Target Profile</span>
                  <span className="block text-lg font-black text-[#00FF88] mt-1 font-mono uppercase">{rankingResult.profile}</span>
                </div>
                <div className="bg-[#03060a]/40 border border-white/[0.02] rounded-xl p-4">
                  <span className="block text-[9px] text-neutral-500 uppercase font-mono tracking-wider font-bold">// Target Ranked Files</span>
                  <span className="block text-lg font-black text-white mt-1 font-mono">{rankingResult.rankedEntries} <span className="text-[10px] text-neutral-600">/ {rankingResult.totalEntries} total</span></span>
                </div>
                <div className="bg-[#03060a]/40 border border-white/[0.02] rounded-xl p-4">
                  <span className="block text-[9px] text-neutral-500 uppercase font-mono tracking-wider font-bold">// Target Selected</span>
                  <span className="block text-lg font-black text-white mt-1 font-mono">{rankingResult.selectedEntries.length} files</span>
                </div>
                <div className="bg-[#03060a]/40 border border-white/[0.02] rounded-xl p-4">
                  <span className="block text-[9px] text-neutral-500 uppercase font-mono tracking-wider font-bold font-semibold">// Computation Est</span>
                  <span className="block text-lg font-black text-[#00FFFF] mt-1 font-mono">{rankingResult.estimatedScanMs} ms</span>
                </div>
              </div>

              {/* Budget Limit Telemetry Banner */}
              <div className="flex flex-wrap items-center justify-between gap-3 text-[10px] bg-white/[0.01] border border-white/[0.03] px-4 py-2.5 rounded-xl mb-5 font-mono select-none">
                <div className="flex flex-wrap gap-4 text-neutral-400">
                  <span>BUDGET LIMITS —</span>
                  <span>MAX_FILES: <span className="text-white">{rankingResult.maxFilesScanned} max</span></span>
                  <span>MAX_BYTES: <span className="text-white">{(rankingResult.maxTotalBytes / (1024 * 1024)).toFixed(0)}MB</span></span>
                </div>
                {rankingResult.truncated ? (
                  <span className="text-amber-400 animate-pulse uppercase font-black tracking-wider flex items-center gap-1">
                    ⚠️ TRUNCATED BY CURRENT PROFILE LIMITS
                  </span>
                ) : (
                  <span className="text-[#00FF88] uppercase font-black tracking-wider">
                    ✓ DETERMINISTIC TARGET BOUNDS COMPLETE
                  </span>
                )}
              </div>

              {/* Interactive filter search for ranked results */}
              <div className="relative mb-4">
                <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 text-neutral-500" size={14} />
                <input 
                  type="text"
                  placeholder="Filter evaluated risk entities..."
                  value={rankingSearch}
                  onChange={(e) => setRankingSearch(e.target.value)}
                  className="w-full bg-[#03060a]/40 border border-white/[0.04] focus:border-[#00FF88]/40 focus:ring-0 rounded-xl px-4 py-2.5 pl-10 text-xs text-white placeholder-neutral-500 outline-none transition-all"
                />
              </div>

              {/* Ranked file items display */}
              {(() => {
                const filteredRanked = rankingResult.selectedEntries.filter((e: any) =>
                  e.path.toLowerCase().includes(rankingSearch.toLowerCase())
                );

                if (filteredRanked.length === 0) {
                  return (
                    <div className="border border-white/[0.02] bg-[#0d1117]/30 rounded-xl p-10 text-center text-xs text-neutral-500 font-mono">
                      // No risk-ranked entry matches current filter query.
                    </div>
                  );
                }

                return (
                  <div className="border border-white/[0.03] bg-neutral-950/40 rounded-xl overflow-hidden shadow-inner">
                    <div className="grid grid-cols-12 gap-2 px-4 py-2 bg-white/[0.01] border-b border-white/[0.05] font-mono text-[9px] uppercase font-bold text-neutral-400 select-none">
                      <div className="col-span-8 md:col-span-9">Vulnerability Risk Entry / Score Trigger Checklist</div>
                      <div className="col-span-2 text-center md:col-span-1">Depth</div>
                      <div className="col-span-2 text-right md:col-span-2">Exposure Weight</div>
                    </div>

                    <div className="divide-y divide-white/[0.03] max-h-[350px] overflow-y-auto">
                      {filteredRanked.map((entry: any, i: number) => {
                        // Determine risk color tier
                        let scoreBg = 'bg-neutral-800 text-neutral-400 border-neutral-700';
                        let scoreGleam = '';
                        if (entry.score >= 25) {
                          scoreBg = 'bg-red-500/10 text-red-400 border-red-500/30';
                          scoreGleam = 'shadow-[0_0_8px_rgba(239,68,68,0.2)]';
                        } else if (entry.score >= 15) {
                          scoreBg = 'bg-amber-500/10 text-amber-400 border-amber-500/30';
                        } else if (entry.score >= 2) {
                          scoreBg = 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30';
                        }

                        return (
                          <div key={i} className="px-4 py-3.5 hover:bg-white/[0.01] transition-colors flex flex-col md:grid md:grid-cols-12 gap-2 items-start md:items-center text-xs font-mono animate-fade-in">
                            <div className="md:col-span-8 lg:col-span-9 w-full">
                              <div className="flex flex-wrap items-center gap-2 mb-1.5">
                                <span className="text-[10px] text-neutral-500 select-none">// {i+1}</span>
                                <span className="text-white font-bold tracking-tight select-all truncate max-w-full block">
                                  {entry.path}
                                </span>
                                {entry.size !== undefined && (
                                  <span className="text-[9px] text-neutral-500 select-none">
                                    ({(entry.size / 1024).toFixed(2)} KB)
                                  </span>
                                )}
                              </div>
                              
                              {/* Trigger Checklist Explanations */}
                              <div className="ml-5 flex flex-col gap-0.5 mt-1 border-l border-white/[0.04] pl-3">
                                {entry.reasons.map((reason: string, ri: number) => (
                                  <span key={ri} className="text-[10px] text-[#8B949E] flex items-center gap-1">
                                    <span className="text-neutral-600 block flex-shrink-0">•</span>
                                    {reason}
                                  </span>
                                ))}
                              </div>
                            </div>

                            <div className="hidden md:block col-span-2 md:col-span-1 text-center text-neutral-400">
                              {entry.depth}
                            </div>

                            <div className="col-span-2 text-right w-full md:w-auto md:col-span-2 flex justify-between md:justify-end items-center gap-2 mt-2 md:mt-0 pt-2 md:pt-0 border-t md:border-t-0 border-white/[0.03]">
                              <span className="inline md:hidden text-[9px] text-neutral-500 font-bold uppercase">// RISK SCORE</span>
                              <span className={`px-2.5 py-1 text-xs font-bold rounded-lg border leading-none font-mono ${scoreBg} ${scoreGleam}`}>
                                {entry.score} pts
                              </span>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                );
              })()}

              {/* CONTENT ACQUISITION LAYER */}
              <div className="mt-8 border-t border-white/[0.06] pt-8">
                <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between mb-6 gap-3">
                  <div>
                    <span className="text-[10px] text-[#00FFFF] uppercase tracking-[0.2em] font-extrabold font-mono">// PHASE 02: TARGET EXTRACTION</span>
                    <h3 className="text-lg font-black text-white uppercase tracking-wider flex items-center gap-2 mt-1">
                      <FileCode className="text-[#00FFFF]" size={18} />
                      Safe Content Retrieval Layer
                    </h3>
                  </div>
                  {!fetchedContentResult && !fetchingContent && (
                    <button
                      onClick={runContentFetch}
                      className="px-4 py-2 bg-[#00FFFF] hover:bg-[#00FFFF]/90 text-neutral-950 font-black text-[10px] uppercase tracking-widest rounded-lg transition-all cursor-pointer shadow-[0_2px_15px_rgba(0,255,255,0.2)]"
                    >
                      Extract Content
                    </button>
                  )}
                </div>

                {!fetchedContentResult && !fetchingContent && !fetchingContentError && (
                  <div className="bg-[#03060a]/20 border border-white/[0.02] rounded-xl p-6 text-center">
                    <p className="text-xs text-neutral-400 mb-4 leading-relaxed max-w-xl mx-auto">
                      Extracts prioritized file structures into memory under deterministic resource controls. Limits are strictly guarded on character lengths, size bounds, and timeout windows.
                    </p>
                    <button
                      onClick={runContentFetch}
                      className="inline-flex items-center gap-2 px-6 py-3 bg-white/[0.02] hover:bg-white/[0.05] border border-[#00FFFF]/30 hover:border-[#00FFFF]/80 text-[#00FFFF] font-black text-[10px] uppercase tracking-wider rounded-xl transition-all cursor-pointer"
                    >
                      <Download size={12} />
                      Initialize Safely (Extracts {rankingResult.selectedEntries.length} Prioritized Targets)
                    </button>
                  </div>
                )}

                {fetchingContent && (
                  <div className="flex flex-col items-center justify-center py-16 space-y-4 bg-[#03060a]/20 border border-white/[0.02] rounded-xl">
                    <RefreshCw className="animate-spin text-[#00FFFF]" size={28} />
                    <div className="text-center font-mono">
                      <span className="text-xs text-[#00FFFF] uppercase tracking-wider font-bold block animate-pulse">// STREAMING BYTES FROM TARGET ENDPOINTS</span>
                      <span className="text-[9px] text-neutral-500 block mt-1 uppercase">// Guarded on character length, size, and timeout ceilings</span>
                    </div>
                  </div>
                )}

                {fetchingContentError && (
                  <div className="border border-red-500/10 bg-red-500/[0.01] rounded-xl p-6 text-center">
                    <p className="text-neutral-400 text-xs font-mono mb-4">{fetchingContentError}</p>
                    <button
                      onClick={runContentFetch}
                      className="px-4 py-2 bg-red-400/10 hover:bg-red-400/20 text-red-300 border border-red-400/30 text-[10px] uppercase font-black tracking-widest rounded-lg cursor-pointer transition-all"
                    >
                      Retry Acquisition
                    </button>
                  </div>
                )}

                {fetchedContentResult && (
                  <div className="space-y-6 animate-fade-in text-neutral-300">
                    
                    {/* Extraction Stats */}
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                      <div className="bg-[#03060a]/40 border border-white/[0.02] rounded-xl p-4">
                        <span className="block text-[8px] text-neutral-500 uppercase font-mono tracking-wider font-bold">// Files Requested</span>
                        <span className="block text-base font-black text-white mt-1 font-mono">{fetchedContentResult.filesRequested} files</span>
                      </div>
                      <div className="bg-[#03060a]/40 border border-white/[0.02] rounded-xl p-4">
                        <span className="block text-[8px] text-neutral-500 uppercase font-mono tracking-wider font-bold">// Files Succeeded</span>
                        <span className="block text-base font-black text-[#00FF88] mt-1 font-mono">{fetchedContentResult.filesFetched} fetched</span>
                      </div>
                      <div className="bg-[#03060a]/40 border border-white/[0.02] rounded-xl p-4">
                        <span className="block text-[8px] text-neutral-500 uppercase font-mono tracking-wider font-bold">// Total Budget Consumed</span>
                        <span className="block text-base font-black text-[#00FFFF] mt-1 font-mono">{(fetchedContentResult.bytesFetched / 1024).toFixed(2)} KB</span>
                      </div>
                      <div className="bg-[#03060a]/40 border border-white/[0.02] rounded-xl p-4">
                        <span className="block text-[8px] text-neutral-500 uppercase font-mono tracking-wider font-bold">// Profile Threshold Status</span>
                        {fetchedContentResult.truncated ? (
                          <span className="block text-[10px] font-black text-amber-400 mt-2 uppercase font-mono tracking-wider animate-pulse">⚠️ Truncated Cutoff</span>
                        ) : (
                          <span className="block text-[10px] font-black text-[#00FF88] mt-2 uppercase font-mono tracking-wider">✓ Within Limits</span>
                        )}
                      </div>
                    </div>

                    {/* Skipped files banner */}
                    {fetchedContentResult.skippedFiles && fetchedContentResult.skippedFiles.length > 0 && (
                      <div className="bg-[#03060a]/40 border border-white/[0.03] p-3 rounded-lg flex items-start gap-2.5">
                        <Ban className="text-amber-500 mt-0.5 flex-shrink-0" size={12} />
                        <div className="text-[10px] font-mono text-[#8B949E]">
                          <span className="text-neutral-400 font-bold uppercase block mb-1">Excluded elements ({fetchedContentResult.skippedFiles.length}) :</span>
                          <span className="break-all">{fetchedContentResult.skippedFiles.join(', ')}</span>
                        </div>
                      </div>
                    )}

                    {/* Master-Detail Panel */}
                    <div className="border border-white/[0.04] bg-neutral-950/20 rounded-xl overflow-hidden grid grid-cols-1 md:grid-cols-12 min-h-[400px]">
                      
                      {/* Left: Fetched items sidebar (col-span-4) */}
                      <div className="md:col-span-4 border-r border-white/[0.04] bg-[#03060a]/30 flex flex-col">
                        <div className="bg-white/[0.01] border-b border-white/[0.04] px-3.5 py-2 select-none">
                          <span className="text-[9px] font-mono font-bold uppercase tracking-wider text-neutral-500">// EXTRACTED FILES</span>
                        </div>
                        <div className="divide-y divide-white/[0.02] overflow-y-auto max-h-[300px] md:max-h-[450px]">
                          {fetchedContentResult.files.map((f: any, fi: number) => {
                            const isSelected = selectedFileForPreview?.path === f.path;
                            return (
                              <button
                                key={fi}
                                onClick={() => setSelectedFileForPreview(f)}
                                className={`w-full text-left px-3.5 py-3 transition-all font-mono text-[11px] flex flex-col gap-1 cursor-pointer ${
                                  isSelected
                                    ? 'bg-[#00FFFF]/5 border-l-2 border-[#00FFFF] text-[#00FFFF]'
                                    : 'hover:bg-white/[0.01] text-neutral-400 hover:text-neutral-300'
                                }`}
                              >
                                <span className="font-semibold select-none truncate block w-full">{f.path.split('/').pop()}</span>
                                <span className="text-[9px] text-neutral-500 truncate select-none block w-full">{f.path}</span>
                                <div className="flex items-center gap-2 mt-1">
                                  <span className="text-[8px] px-1 bg-white/[0.03] text-neutral-500 border border-white/[0.05] rounded font-bold font-sans">
                                    {(f.size / 1024).toFixed(1)} KB
                                  </span>
                                  {f.truncatedContent && (
                                    <span className="text-[8px] font-bold px-1 bg-amber-400/10 text-amber-400 border border-amber-400/20 rounded font-sans">
                                      TRUNCATED
                                    </span>
                                  )}
                                </div>
                              </button>
                            );
                          })}
                        </div>
                      </div>

                      {/* Right: Rich Viewer (col-span-8) */}
                      <div className="md:col-span-8 bg-[#000000]/60 flex flex-col">
                        {selectedFileForPreview ? (
                          <div className="flex flex-col h-full">
                            <div className="bg-white/[0.01] border-b border-white/[0.04] px-4 py-2.5 flex justify-between items-center bg-[#070b11]">
                              <div className="flex flex-col">
                                <span className="text-[10px] text-neutral-400 font-mono select-all truncate max-w-xs md:max-w-md block">{selectedFileForPreview.path}</span>
                                <span className="text-[8px] font-mono text-neutral-600 block mt-0.5 uppercase">File Weight: {(selectedFileForPreview.size / 1024).toFixed(2)} KB ({selectedFileForPreview.size} bytes)</span>
                              </div>
                              {selectedFileForPreview.truncatedContent && (
                                <span className="px-2 py-0.5 bg-amber-400/10 text-amber-400 border border-amber-400/30 text-[8px] font-black uppercase tracking-wider rounded font-mono animate-pulse">
                                  TRUNCATED BY CHAR LIMITS
                                </span>
                              )}
                            </div>

                            <div className="p-4 overflow-auto max-h-[300px] md:max-h-[400px] font-mono text-xs text-[#E1E4E8] leading-relaxed bg-[#03060a]/65 flex-1 relative select-text">
                              <pre className="whitespace-pre overflow-x-auto">
                                <code>
                                  {selectedFileForPreview.content}
                                </code>
                              </pre>
                            </div>
                          </div>
                        ) : (
                          <div className="flex flex-col items-center justify-center p-12 text-center text-xs text-neutral-500 font-mono min-h-[300px]">
                            // Click an extracted item from the sidebar directory listing to verify.
                          </div>
                        )}
                      </div>

                    </div>

                    {/* PHASE 03: DETERMINISTIC STATIC SCAN ENGINE */}
                    <div className="mt-8 border-t border-white/[0.06] pt-8">
                      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between mb-6 gap-3">
                        <div>
                          <span className="text-[10px] text-pink-400 uppercase tracking-[0.2em] font-extrabold font-mono">// PHASE 03: PATTERN SCANNING MATRIX</span>
                          <h3 className="text-lg font-black text-white uppercase tracking-wider flex items-center gap-2 mt-1">
                            <Shield className="text-pink-400 animate-pulse" size={18} />
                            Deterministic Static Scan Engine
                          </h3>
                        </div>
                        
                        {!scanResult && !scanning && (
                          <button
                            onClick={runDeterministicScan}
                            className="px-5 py-2 bg-pink-500 hover:bg-pink-600 text-white font-black text-[10px] uppercase tracking-widest rounded-lg transition-all cursor-pointer shadow-[0_2px_15px_rgba(236,72,153,0.3)] flex items-center gap-1.5"
                          >
                            <Shield size={12} />
                            Run Deterministic Scan
                          </button>
                        )}
                      </div>

                      {scanning && (
                        <div className="flex flex-col items-center justify-center py-16 space-y-4 bg-pink-950/5 border border-pink-500/20 rounded-xl">
                          <RefreshCw className="animate-spin text-pink-500" size={28} />
                          <div className="text-center font-mono">
                            <span className="text-xs text-pink-400 uppercase tracking-wider font-bold block animate-pulse">// RECONSTRUCTING BUFFER SEGMENTS / RESOLVING REGULAR EXPRESSIONS</span>
                            <span className="text-[9px] text-neutral-500 block mt-1 uppercase">// Checking for hardcoded secrets, misconfigurations, and ownership exploits</span>
                          </div>
                        </div>
                      )}

                      {scanError && (
                        <div className="border border-red-500/10 bg-red-500/[0.01] rounded-xl p-6 text-center">
                          <p className="text-neutral-400 text-xs font-mono mb-4">{scanError}</p>
                          <button
                            onClick={runDeterministicScan}
                            className="px-4 py-2 bg-red-400/10 hover:bg-red-400/20 text-red-300 border border-red-400/30 text-[10px] uppercase font-black tracking-widest rounded-lg cursor-pointer transition-all"
                          >
                            Retry Scan Engine
                          </button>
                        </div>
                      )}

                      {!scanResult && !scanning && !scanError && (
                        <div className="bg-[#03060a]/20 border border-white/[0.02] rounded-xl p-6 text-center">
                          <p className="text-xs text-neutral-400 mb-4 leading-relaxed max-w-xl mx-auto font-sans">
                            Execute deterministic checks (regex matches, configuration triggers, and vulnerable path checkouts) on retrieved buffers referencing our verified 20+ signal core registry.
                          </p>
                          <button
                            onClick={runDeterministicScan}
                            className="inline-flex items-center gap-2 px-6 py-3 bg-[#e91e63]/10 hover:bg-[#e91e63]/15 border border-[#e91e63]/40 hover:border-[#e91e63]/80 text-pink-400 font-extrabold text-[10px] uppercase tracking-wider rounded-xl transition-all cursor-pointer"
                          >
                            <ShieldCheck size={13} />
                            Initialize Scanning Matrix (Runs 20+ active rules)
                          </button>
                        </div>
                      )}

                      {scanResult && (
                        <div className="space-y-6 animate-fade-in text-neutral-300">
                          
                          {/* Scan Summary Metrics Row */}
                          <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
                            <div className="bg-red-950/10 border border-red-500/25 rounded-xl p-4">
                              <span className="block text-[8px] text-red-400 uppercase font-mono tracking-wider font-bold">// CRITICAL LEAKS</span>
                              <span className="block text-xl font-black text-red-400 mt-1 font-mono">{scanResult.summary.critical}</span>
                            </div>
                            <div className="bg-orange-950/10 border border-orange-500/25 rounded-xl p-4">
                              <span className="block text-[8px] text-orange-400 uppercase font-mono tracking-wider font-bold">// HIGH DANGER</span>
                              <span className="block text-xl font-black text-orange-400 mt-1 font-mono">{scanResult.summary.high}</span>
                            </div>
                            <div className="bg-amber-950/10 border border-amber-500/25 rounded-xl p-4">
                              <span className="block text-[8px] text-amber-400 uppercase font-mono tracking-wider font-bold">// MEDIUM EXPOSURE</span>
                              <span className="block text-xl font-black text-amber-400 mt-1 font-mono">{scanResult.summary.medium}</span>
                            </div>
                            <div className="bg-blue-950/10 border border-blue-500/25 rounded-xl p-4">
                              <span className="block text-[8px] text-blue-400 uppercase font-mono tracking-wider font-bold">// LOW WARNING</span>
                              <span className="block text-xl font-black text-blue-400 mt-1 font-mono">{scanResult.summary.low}</span>
                            </div>
                            <div className="bg-neutral-900/40 border border-white/[0.04] rounded-xl p-4 col-span-2 md:col-span-1">
                              <span className="block text-[8px] text-neutral-500 uppercase font-mono tracking-wider font-bold">// DISCOVERED LEAKS</span>
                              <span className="block text-xl font-black text-white mt-1 font-mono">
                                {scanResult.findings.length}
                              </span>
                            </div>
                          </div>

                          {/* Scope indicators bar */}
                          <div className="bg-[#03060a]/40 border border-white/[0.03] px-4 py-3 rounded-xl flex flex-wrap justify-between items-center text-[10px] font-mono gap-4">
                            <div className="flex items-center gap-4 text-neutral-400">
                              <span>SCANNED: <strong className="text-white">{scanResult.scope.filesScanned}</strong> files</span>
                              <span className="text-neutral-700">|</span>
                              <span>SKIPPED: <strong className="text-white">{scanResult.scope.filesSkipped}</strong> files</span>
                              <span className="text-neutral-700">|</span>
                              <span>BUDGET SIZE: <strong className="text-white">{(scanResult.scope.bytesScanned / 1024).toFixed(2)} KB</strong></span>
                            </div>
                            <div className="flex items-center gap-2">
                              <span className="text-neutral-500 uppercase font-bold text-[9px]">// SYSTEM TIME:</span>
                              <span className="text-pink-400 font-bold">{new Date(scanResult.generatedAt).toLocaleTimeString()}</span>
                            </div>
                          </div>

                          {/* Findings visual output detail section */}
                          <div className="border border-white/[0.04] bg-neutral-950/20 rounded-xl overflow-hidden grid grid-cols-1 md:grid-cols-12 min-h-[420px]">
                            
                            {/* Sidebar: Findings selection */}
                            <div className="md:col-span-5 border-r border-white/[0.04] bg-[#03060a]/30 flex flex-col">
                              <div className="bg-white/[0.01] border-b border-white/[0.04] px-3.5 py-2 flex justify-between items-center bg-[#070b11]">
                                <span className="text-[9px] font-mono font-bold uppercase tracking-wider text-neutral-400">// FINDINGS LOG ({scanResult.findings.length})</span>
                              </div>

                              <div className="divide-y divide-white/[0.02] overflow-y-auto max-h-[350px] md:max-h-[480px]">
                                {scanResult.findings.length === 0 ? (
                                  <div className="p-16 text-center text-xs text-emerald-400 font-mono">
                                    // Clean report. Zero deterministic findings found.
                                  </div>
                                ) : (
                                  scanResult.findings.map((f: Finding) => {
                                    const isSelected = selectedFindingForDrilldown?.id === f.id;
                                    
                                    let pillColor = 'text-blue-400 bg-blue-500/10 border-blue-500/20';
                                    if (f.severity === 'critical') pillColor = 'text-red-400 bg-red-500/15 border-red-500/30 font-bold animate-pulse';
                                    else if (f.severity === 'high') pillColor = 'text-orange-400 bg-orange-500/15 border-orange-500/30';
                                    else if (f.severity === 'medium') pillColor = 'text-amber-400 bg-amber-500/15 border-amber-500/30';

                                    return (
                                      <button
                                        key={f.id}
                                        onClick={() => setSelectedFindingForDrilldown(f)}
                                        className={`w-full text-left px-4 py-3.5 transition-all flex flex-col gap-1.5 cursor-pointer border-l-2 ${
                                          isSelected
                                            ? 'bg-pink-500/[0.03] border-[#e91e63] text-pink-400'
                                            : 'border-transparent hover:bg-white/[0.01] text-neutral-400 hover:text-neutral-300'
                                        }`}
                                      >
                                        <div className="flex justify-between items-center gap-2">
                                          <span className="font-mono text-[9px] text-neutral-500 truncate max-w-[140px]" title={f.filePath}>
                                            {f.filePath.split('/').pop()}
                                          </span>
                                          <span className={`text-[8px] px-1.5 py-0.2 border rounded-md uppercase font-mono font-black ${pillColor}`}>
                                            {f.severity}
                                          </span>
                                        </div>

                                        <h4 className="font-extrabold text-[11px] text-white line-clamp-1 leading-snug">
                                          {f.title}
                                        </h4>

                                        <div className="flex justify-between items-center text-[9px] text-neutral-500 font-mono">
                                          <span>Line: {f.lineStart}</span>
                                          <span>Conf: {(f.confidence * 100).toFixed(0)}%</span>
                                        </div>
                                      </button>
                                    );
                                  })
                                )}
                              </div>
                            </div>

                            {/* Detail Panel */}
                            <div className="md:col-span-7 bg-[#000000]/65 flex flex-col overflow-y-auto max-h-[520px]">
                              {selectedFindingForDrilldown ? (
                                <div className="flex flex-col h-full text-xs animate-fade-in">
                                  
                                  {/* Header meta */}
                                  <div className="p-4 bg-[#070b11] border-b border-white/[0.04]">
                                    <div className="text-[8px] font-mono text-[#8B949E] uppercase tracking-wider select-none mb-1">// SYSTEM EXPOSURE MATCHED</div>
                                    <h3 className="font-black text-sm text-white mb-2 leading-tight uppercase select-text">{selectedFindingForDrilldown.title}</h3>
                                    <div className="flex flex-wrap items-center gap-2 font-mono text-[9px]">
                                      <span className="text-[#00FFFF] font-bold">{selectedFindingForDrilldown.ruleId}</span>
                                      <span className="text-neutral-600">•</span>
                                      <span className="text-neutral-400 truncate max-w-xs">{selectedFindingForDrilldown.filePath} : Line {selectedFindingForDrilldown.lineStart}</span>
                                    </div>
                                  </div>

                                  {/* Drilldown details */}
                                  <div className="p-5 space-y-4">
                                    
                                    {/* Info Box */}
                                    <div>
                                      <span className="block text-[8px] text-neutral-500 font-mono font-bold uppercase tracking-wider mb-1.5">// Trigger Explanation</span>
                                      <div className="p-3 bg-neutral-950/40 border border-white/[0.03] rounded-lg text-neutral-300 font-sans leading-relaxed select-text">
                                        {selectedFindingForDrilldown.explanation}
                                      </div>
                                    </div>

                                    {/* Evidence code segments */}
                                    <div>
                                      <span className="block text-[8px] text-neutral-500 font-mono font-bold uppercase tracking-wider mb-1.5">// Offending Code Evidence</span>
                                      <div className="p-3 bg-[#03060a]/90 border border-red-500/20 text-red-200 rounded-lg font-mono text-[11px] break-all select-all shadow-inner">
                                        {selectedFindingForDrilldown.evidence}
                                      </div>
                                    </div>

                                    {/* Path details */}
                                    <div>
                                      <span className="block text-[8px] text-neutral-500 font-mono font-bold uppercase tracking-wider mb-1.5">// Compliant Remediation Instruction</span>
                                      <div className="p-4 bg-emerald-950/15 border border-emerald-500/20 text-emerald-300 rounded-lg font-sans leading-relaxed text-xs">
                                        <div className="flex items-start gap-2.5">
                                          <CheckCircle2 className="text-emerald-400 mt-0.5 flex-shrink-0" size={14} />
                                          <span>{selectedFindingForDrilldown.remediation}</span>
                                        </div>
                                      </div>
                                    </div>

                                    {/* Deterministic Prompt Pack Panel */}
                                    {selectedFindingForDrilldown.promptPack && (
                                      <div className="border border-pink-500/35 bg-pink-950/5 rounded-xl p-5 mt-6 relative overflow-hidden backdrop-blur-sm shadow-[0_4px_20px_rgba(236,72,153,0.08)]">
                                        <div className="absolute top-0 right-0 w-24 h-24 bg-pink-500/5 blur-3xl rounded-full"></div>
                                        
                                        <div className="flex items-center justify-between mb-4 border-b border-pink-500/10 pb-3 gap-2">
                                          <div className="flex items-center gap-2.5 min-w-0">
                                            <div className="p-1.5 bg-pink-500/10 border border-pink-500/30 rounded-lg text-pink-400 shrink-0">
                                              <Sparkles size={14} className="animate-pulse" />
                                            </div>
                                            <div className="min-w-0">
                                              <span className="block text-[8px] text-pink-400 uppercase font-mono font-extrabold tracking-wider">// Deterministic Repair Payload</span>
                                              <h4 className="text-xs font-black text-white uppercase tracking-wider truncate select-text">
                                                {selectedFindingForDrilldown.promptPack.title}
                                              </h4>
                                            </div>
                                          </div>

                                          <button
                                            onClick={() => handleCopyPromptPack(selectedFindingForDrilldown.id, selectedFindingForDrilldown.promptPack.aiRepairPrompt)}
                                            className={`px-3 py-1.5 rounded-lg text-[9px] uppercase font-black tracking-widest flex items-center gap-1.5 transition-all cursor-pointer shrink-0 border ${
                                              copiedPromptId === selectedFindingForDrilldown.id
                                                ? 'bg-emerald-500/15 text-emerald-400 border-emerald-500/40'
                                                : 'bg-pink-500/10 hover:bg-pink-500/20 text-pink-300 border-pink-500/30 hover:border-pink-500/50'
                                            }`}
                                          >
                                            <Copy size={11} />
                                            {copiedPromptId === selectedFindingForDrilldown.id ? 'Copied' : 'Copy Prompt Pack'}
                                          </button>
                                        </div>

                                        <div className="space-y-4">
                                          {/* Summary of trigger */}
                                          <div className="space-y-1">
                                            <span className="text-[8px] text-neutral-500 font-mono font-bold uppercase tracking-wider block">// Prompt Summary</span>
                                            <p className="text-neutral-300 font-sans leading-relaxed text-xs select-text">
                                              {selectedFindingForDrilldown.promptPack.summary}
                                            </p>
                                          </div>

                                          {/* Risk */}
                                          <div className="space-y-1">
                                            <span className="text-[8px] text-neutral-500 font-mono font-bold uppercase tracking-wider block">// Risk Assessment</span>
                                            <p className="text-neutral-400 font-sans leading-relaxed text-[11px] bg-black/20 p-2.5 rounded-lg border border-white/[0.03] select-text">
                                              {selectedFindingForDrilldown.promptPack.risk}
                                            </p>
                                          </div>

                                          {/* Fix Steps Checklist */}
                                          <div className="space-y-2">
                                            <span className="text-[8px] text-neutral-500 font-mono font-bold uppercase tracking-wider block">// Step-by-Step Remediation</span>
                                            <div className="space-y-2">
                                              {selectedFindingForDrilldown.promptPack.fixSteps.map((step: string, idx: number) => (
                                                <div key={idx} className="flex items-start gap-2 text-[11px] text-neutral-300 bg-white/[0.01] p-2 rounded-md border border-white/[0.02]">
                                                  <span className="text-[10px] bg-pink-500/15 border border-pink-500/20 text-pink-400 w-4 h-4 rounded flex items-center justify-center font-mono font-bold shrink-0 mt-0.5">
                                                    {idx + 1}
                                                  </span>
                                                  <span className="leading-normal select-text">{step}</span>
                                                </div>
                                              ))}
                                            </div>
                                          </div>

                                          {/* Collapsible Prompt Preview block */}
                                          <div className="space-y-1.5 pt-2">
                                            <span className="text-[8px] text-neutral-500 font-mono font-bold uppercase tracking-wider block">// Raw AI Prompt Preview (Includes full rules context)</span>
                                            <div className="p-3 bg-neutral-950/80 border border-pink-500/10 rounded-lg text-neutral-500 font-mono text-[9px] max-h-[140px] overflow-y-auto scrollbar-thin scrollbar-thumb-pink-500/20">
                                              <pre className="whitespace-pre-wrap leading-relaxed select-text text-neutral-400 font-mono font-bold">
                                                {selectedFindingForDrilldown.promptPack.aiRepairPrompt}
                                              </pre>
                                            </div>
                                          </div>
                                        </div>
                                      </div>
                                    )}

                                  </div>
                                </div>
                              ) : (
                                <div className="flex-1 flex flex-col items-center justify-center p-12 text-center text-xs text-neutral-500 font-mono min-h-[300px]">
                                  <span>// SELECT A DETECTIVE FINDING ON THE SIDEBAR TO DRILLDOWN LOGIC AND REMEDIATIONS</span>
                                </div>
                              )}
                            </div>

                          </div>
                        </div>
                      )}

                    </div>

                  </div>
                )}

              </div>

            </div>
          ) : (
            <div className="border border-dashed border-white/[0.05] bg-white/[0.01]/30 rounded-2xl p-10 text-center text-xs text-neutral-500 font-mono">
              // Click "Calculate Risk Prioritization" above to parse attack surface weights.
            </div>
          )}
        </section>
      )}

      {/* DIRECTORY TREE INTERACTIVE METADATA VIEW */}
      {showTreePanel && (
        <section className="glass-card rounded-2xl p-6 border border-white/[0.03] bg-white/[0.01] shadow-2xl mb-8 animate-fade-in">
          <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center border-b border-white/[0.04] pb-4 mb-6 gap-4">
            <div>
              <p className="text-[10px] text-[#00FFFF] uppercase tracking-[0.2em] font-extrabold mb-1 font-mono">// SRC TREE SOLVER</p>
              <h2 className="text-xl font-black text-white uppercase tracking-wider">Repository Directory Assembly</h2>
            </div>
            {selectedRepo && (
              <span className="px-3 py-1 bg-white/[0.02] border border-[#00FFFF]/20 text-[10px] uppercase font-black text-[#00FFFF] font-mono rounded-lg flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 bg-[#00FFFF] rounded-full animate-ping"></span>
                {selectedRepo.owner}/{selectedRepo.name}
              </span>
            )}
          </div>

          {treeLoading ? (
            <div className="flex flex-col items-center justify-center py-16 space-y-3">
              <RefreshCw className="animate-spin text-[#00FFFF]" size={24} />
              <span className="font-mono text-xs text-[#8B949E]">// Fetching Git trees recursively...</span>
            </div>
          ) : treeError ? (
            <div className="border border-red-500/20 bg-red-500/[0.02] rounded-xl p-6 text-center animate-fade-in">
              <p className="text-xs text-red-100 font-mono mb-3">{treeError}</p>
              <button 
                onClick={() => selectedRepo && fetchTree(selectedRepo)}
                className="px-4 py-2 bg-red-400/10 hover:bg-red-400/20 text-red-300 border border-red-400/20 text-[10px] uppercase font-black tracking-widest rounded-lg cursor-pointer transition-all"
              >
                Re-verify Link
              </button>
            </div>
          ) : treeResult ? (
            <div className="animate-fade-in text-neutral-300">
              {/* Dynamic Telemetry stats block */}
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-6">
                <div className="bg-[#03060a]/40 border border-white/[0.02] rounded-xl p-4 flex flex-col justify-between">
                  <span className="block text-[10px] text-neutral-500 uppercase font-mono tracking-wider font-bold">// Target Total Elements</span>
                  <span className="block text-2xl font-black text-white mt-1 font-mono">{treeResult.totalEntries}</span>
                </div>
                <div className="bg-[#03060a]/40 border border-white/[0.02] rounded-xl p-4 flex flex-col justify-between">
                  <span className="block text-[10px] text-neutral-500 uppercase font-mono tracking-wider font-bold">// Returned Safe Elements</span>
                  <span className="block text-2xl font-black text-[#00FF88] mt-1 font-mono">{treeResult.returnedEntries}</span>
                </div>
                <div className="bg-[#03060a]/40 border border-white/[0.02] rounded-xl p-4 flex flex-col justify-between">
                  <span className="block text-[10px] text-neutral-500 uppercase font-mono tracking-wider font-bold">// Truncation Flag</span>
                  <span className={`block text-xs font-bold uppercase mt-2.5 font-mono ${treeResult.truncated ? 'text-amber-400 animate-pulse' : 'text-[#00FF88]'}`}>
                    {treeResult.truncated ? '⚠️ Active (LIMIT EXCEEDED)' : '✓ Normal (Within Limit)'}
                  </span>
                </div>
              </div>

              {/* Tree filtration tool row */}
              <div className="relative mb-5">
                <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 text-neutral-500" size={14} />
                <input 
                  type="text"
                  placeholder="Filter directory tree files & components..."
                  value={treeSearch}
                  onChange={(e) => setTreeSearch(e.target.value)}
                  className="w-full bg-[#03060a]/40 border border-white/[0.04] focus:border-[#00FFFF]/40 focus:ring-0 rounded-xl px-4 py-2.5 pl-10 text-xs text-white placeholder-neutral-500 outline-none transition-all"
                />
              </div>

              {/* Content directory results layout */}
              {filteredTreeEntries.length === 0 ? (
                <div className="border border-white/[0.02] bg-[#0d1117]/30 rounded-xl p-10 text-center text-xs text-neutral-500 font-mono">
                  // No directory paths matching current tree filter.
                </div>
              ) : (
                <div className="border border-white/[0.03] bg-neutral-950/40 rounded-xl overflow-hidden shadow-inner">
                  {/* Table headers */}
                  <div className="grid grid-cols-12 gap-2 px-4 py-2 border-b border-white/[0.05] bg-white/[0.01 ] font-mono text-[9px] uppercase font-bold text-neutral-400 select-none">
                    <div className="col-span-7 sm:col-span-8">Filesystem Path</div>
                    <div className="col-span-2 text-center">Depth</div>
                    <div className="col-span-1 text-center">Ext</div>
                    <div className="col-span-2 text-right">Size</div>
                  </div>

                  {/* Scroller block */}
                  <div className="divide-y divide-white/[0.01] max-h-[300px] overflow-y-auto">
                    {filteredTreeEntries.map((entry: any, i: number) => {
                      const sizeInKb = entry.size !== undefined ? `${(entry.size / 1024).toFixed(2)} KB` : '-';
                      
                      return (
                        <div key={i} className="grid grid-cols-12 gap-2 px-4 py-1.5 hover:bg-white/[0.01] items-center text-[11px] text-neutral-300 font-mono transition-colors animate-fade-in">
                          <div className="col-span-7 sm:col-span-8 truncate flex items-center gap-2">
                            {entry.type === 'directory' ? (
                              <span className="text-[#FFD700] text-xs">📁</span>
                            ) : (
                              <span className="text-neutral-500 text-xs">📄</span>
                            )}
                            <span className={entry.type === 'directory' ? 'text-white font-semibold' : 'text-neutral-300'}>
                              {entry.path}
                            </span>
                          </div>
                          <div className="col-span-2 text-center text-neutral-400">
                            {entry.depth}
                          </div>
                          <div className="col-span-1 text-center text-neutral-400 select-none uppercase font-bold text-[9px]">
                            {entry.extension || <span className="text-neutral-700">-</span>}
                          </div>
                          <div className="col-span-2 text-right pr-2 text-neutral-400">
                            {sizeInKb}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}
            </div>
          ) : null}
        </section>
      )}

      {/* DETECTIVE DECAY CORE RULE REGISTRY CENTRAL VISUALIZER */}
      <RuleRegistryView />

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
