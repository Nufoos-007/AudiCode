import React, { useState, useEffect } from 'react';
import { Search, LogOut, Code, ShieldAlert, FolderOpen, ArrowRight, RefreshCw, Database, ShieldCheck, Shield, ChevronRight, Calendar, AlertTriangle, GitPullRequest } from 'lucide-react';
import { Repository, ScanReport, SeverityType } from '../types';
import { apiFetch } from '../utils/api';
import { GithubWorkflowView } from './GithubWorkflowView';

interface DashboardViewProps {
  user: { login: string; name: string | null; avatarUrl: string };
  onLogout: () => void;
  onSelectRepo: (repo: Repository) => void;
  onSelectHistoricReport: (report: ScanReport) => void;
}

export function DashboardView({ user, onLogout, onSelectRepo, onSelectHistoricReport }: DashboardViewProps) {
  const [repos, setRepos] = useState<Repository[]>([]);
  const [searchTerm, setSearchTerm] = useState<string>('');
  const [customInput, setCustomInput] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Tabs structure: 'REPOS' (Connect pipeline & list), 'GITHUB' (Github Workflow Integration) or 'HISTORY' (Historical persistent reports list)
  const [activeTab, setActiveTab] = useState<'REPOS' | 'GITHUB' | 'HISTORY'>('REPOS');
  const [typeFilter, setTypeFilter] = useState<'ALL' | 'PUBLIC' | 'PRIVATE'>('ALL');

  // Historical reports
  const [history, setHistory] = useState<ScanReport[]>([]);
  const [loadingHistory, setLoadingHistory] = useState<boolean>(false);
  const [historyError, setHistoryError] = useState<string | null>(null);

  const fetchRepos = () => {
    setLoading(true);
    setError(null);
    apiFetch('/api/repos')
      .then(res => {
        if (!res.ok) throw new Error('Failed to load user repositories from active sessions.');
        return res.json();
      })
      .then(data => {
        setRepos(data.repositories || []);
      })
      .catch(err => {
        setError(err.message || 'Error occurred listing GitHub assets.');
      })
      .finally(() => {
        setLoading(false);
      });
  };

  const fetchHistory = () => {
    setLoadingHistory(true);
    setHistoryError(null);
    apiFetch('/api/scans')
      .then(res => {
        if (!res.ok) throw new Error('Failed to retrieve past scan reports.');
        return res.json();
      })
      .then(data => {
        setHistory(data.reports || []);
      })
      .catch(err => {
        setHistoryError(err.message || 'Error loading scan history metrics.');
      })
      .finally(() => {
        setLoadingHistory(false);
      });
  };

  useEffect(() => {
    fetchRepos();
  }, []);

  const handleCustomScanSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!customInput || !customInput.trim()) return;

    // Support: "github.com/owner/name", "https://github.com/owner/name", "owner/name"
    let cleanHandle = customInput.trim()
      .replace(/^(https?:\/\/)?(www\.)?github\.com\//i, '')
      .replace(/\/$/, '');

    const parts = cleanHandle.split('/');
    if (parts.length < 2) {
      setError('Please provide a valid repository representation formatted as: owner/name (e.g. facebook/react)');
      return;
    }

    const owner = parts[0];
    const name = parts[1];

    // Build temporary repository reference to scan
    const customRepo: Repository = {
      id: `custom-${owner}-${name}`,
      name,
      owner,
      description: 'Manually loaded custom GitHub repository path.',
      isPrivate: false,
      defaultBranch: parts[2] || 'main',
      url: `https://github.com/${owner}/${name}`
    };

    onSelectRepo(customRepo);
  };

  const filteredRepos = repos.filter(repo => {
    const searchLower = searchTerm.toLowerCase();
    const matchesSearch = (
      repo.name.toLowerCase().includes(searchLower) ||
      (repo.description && repo.description.toLowerCase().includes(searchLower)) ||
      repo.owner.toLowerCase().includes(searchLower)
    );

    if (typeFilter === 'PUBLIC') return matchesSearch && !repo.isPrivate;
    if (typeFilter === 'PRIVATE') return matchesSearch && repo.isPrivate;
    return matchesSearch;
  });

  // Calculate grade based on score
  const getGrade = (score: number) => {
    if (score >= 90) return { char: 'A', desc: 'Secure', color: 'text-[#00FF88]', bg: 'bg-[#00FF88]/10', border: 'border-[#00FF88]/20' };
    if (score >= 75) return { char: 'B', desc: 'Safe', color: 'text-[#4D9EFF]', bg: 'bg-[#4D9EFF]/10', border: 'border-[#4D9EFF]/20' };
    if (score >= 55) return { char: 'C', desc: 'Moderate', color: 'text-[#FFD700]', bg: 'bg-[#FFD700]/10', border: 'border-[#FFD700]/20' };
    if (score >= 35) return { char: 'D', desc: 'Warning', color: 'text-[#FF8C00]', bg: 'bg-[#FF8C00]/10', border: 'border-[#FF8C00]/20' };
    return { char: 'F', desc: 'Critical', color: 'text-[#FF4444]', bg: 'bg-[#FF4444]/10', border: 'border-[#FF4444]/20' };
  };

  return (
    <div className="w-full max-w-5xl mx-auto py-6 px-4.5 animate-fade-in">
      {/* Top Header Row with status metrics */}
      <header className="flex justify-between items-center border-b border-white/[0.04] pb-4 mb-6">
        <div className="flex items-center gap-4">
          <img src={user.avatarUrl} alt="avatar" className="w-[42px] h-[42px] rounded-xl border border-white/[0.08] shadow-[0_4px_12px_rgba(0,0,0,0.3)] hover:scale-105 transition-all" referrerPolicy="no-referrer" />
          <div>
            <h3 className="font-display text-sm font-black text-white tracking-wider uppercase">{user.name || user.login}</h3>
            <p className="font-condensed text-[11px] text-[#00FF88] font-bold uppercase tracking-wider">// SYSTEM ROLE: AUDITOR · @{user.login}</p>
          </div>
        </div>

        <button
          onClick={onLogout}
          className="flex items-center gap-2 px-4 py-2 border border-white/[0.06] bg-white/[0.01] hover:bg-red-500/[0.05] hover:text-red-400 hover:border-red-500/30 rounded-xl font-display text-[10px] uppercase font-black tracking-widest text-[#8B949E] cursor-pointer transition-all duration-300 shadow-sm"
        >
          <LogOut size={12} strokeWidth={2.5} />
          Disengage
        </button>
      </header>

      {/* Tabs navigation - Pill selector matching Cursor style */}
      <div className="flex bg-[#0A0E12]/60 p-1.5 border border-white/[0.04] rounded-xl mb-6 max-w-lg shadow-inner">
        <button
          onClick={() => setActiveTab('REPOS')}
          className={`px-5 py-2.5 rounded-lg font-display text-[10px] font-black uppercase tracking-[0.16em] transition-all duration-300 flex items-center justify-center gap-2 cursor-pointer ${
            activeTab === 'REPOS'
              ? 'bg-gradient-to-r from-[#00FF88] to-[#00E575] text-black shadow-[0_4px_20px_rgba(0,255,136,0.18)]'
              : 'text-[#8B949E] hover:text-white'
          }`}
        >
          <Shield size={12} strokeWidth={2.5} />
          CONDUIT PIPELINE
        </button>
        <button
          onClick={() => setActiveTab('GITHUB')}
          className={`px-5 py-2.5 rounded-lg font-display text-[10px] font-black uppercase tracking-[0.16em] transition-all duration-300 flex items-center justify-center gap-2 cursor-pointer ${
            activeTab === 'GITHUB'
              ? 'bg-gradient-to-r from-[#00FF88] to-[#00E575] text-black shadow-[0_4px_20px_rgba(0,255,136,0.18)]'
              : 'text-[#8B949E] hover:text-white'
          }`}
        >
          <GitPullRequest size={12} strokeWidth={2.5} />
          GITHUB INTEGRATIONS
        </button>
        <button
          onClick={() => { setActiveTab('HISTORY'); fetchHistory(); }}
          className={`px-5 py-2.5 rounded-lg font-display text-[10px] font-black uppercase tracking-[0.16em] transition-all duration-300 flex items-center justify-center gap-2 cursor-pointer ${
            activeTab === 'HISTORY'
              ? 'bg-gradient-to-r from-[#00FF88] to-[#00E575] text-black shadow-[0_4px_20px_rgba(0,255,136,0.18)]'
              : 'text-[#8B949E] hover:text-white'
          }`}
        >
          <Database size={12} strokeWidth={2.5} />
          AUDIT LOGS
        </button>
      </div>

      {activeTab === 'REPOS' ? (
        <>
          {/* Hero Manual Input Scan Section */}
          <section className="glass-card rounded-2xl p-5 md:p-6 mb-6 relative overflow-hidden shadow-[0_32px_80px_rgba(0,0,0,0.6)] border border-white/[0.03]">
            <div className="absolute top-0 right-0 p-6 opacity-[0.015] pointer-events-none text-[#00FF88] animate-breathe">
              <ShieldAlert size={160} />
            </div>

            <span className="font-condensed text-[11px] text-[#00FF88] uppercase tracking-[0.2em] block mb-2 font-extrabold">// SYSTEM SCANNER TERMINAL INGESTION</span>
            <h2 className="font-display text-xl md:text-2xl font-black text-white uppercase tracking-wider mb-2">REPOSITORIES STREAM ANALYSIS</h2>
            <p className="font-sans text-xs text-[#8B949E] max-w-lg mb-5 leading-relaxed">Input target branch parameters or Paste a GitHub workspace URL to map syntax propagation flows instantly.</p>

            <form onSubmit={handleCustomScanSubmit} className="flex flex-col sm:flex-row gap-0 max-w-3xl border border-white/[0.06] focus-within:border-[#00FF88]/40 focus-within:shadow-[0_0_25px_rgba(0,255,136,0.06)] rounded-xl overflow-hidden bg-[#03060a]/90 transition-all duration-300 shadow-inner">
              <input
                type="text"
                value={customInput}
                onChange={(e) => setCustomInput(e.target.value)}
                placeholder="github.com/username/your-project or owner/repo"
                className="flex-1 bg-transparent border-0 outline-hidden font-tech text-xs py-2.5 px-4 text-white placeholder-[#484F58] focus:ring-0"
              />
              <button
                type="submit"
                className="bg-gradient-to-r from-[#00FF88] to-[#00E575] text-black font-display font-black text-[10px] uppercase tracking-[0.2em] py-2.5 px-6 hover:shadow-[0_0_20px_rgba(0,255,136,0.3)] hover:scale-[1.01] active:scale-[0.98] cursor-pointer whitespace-nowrap transition-all flex items-center gap-2.5 justify-center"
              >
                Scan Branch
                <ArrowRight size={12} strokeWidth={3} />
              </button>
            </form>
          </section>

          {/* Directory listing segment labels */}
          <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 mb-4 pt-1">
            <div>
              <h3 className="font-display text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2.5">
                <FolderOpen size={15} className="text-[#00FF88]" />
                Your Repositories
              </h3>
              <p className="font-condensed text-[10px] text-[#8B949E] uppercase tracking-widest mt-0.5">{loading ? 'Indexing cloud assets...' : `Discovered ${repos.length} matches`}</p>
            </div>

            {/* Public/Private toggle filters */}
            <div className="flex items-center gap-1 bg-[#0A0D10]/80 border border-white/[0.04] rounded-xl p-1 shadow-inner">
              <button
                onClick={() => setTypeFilter('ALL')}
                className={`px-3 py-1.5 rounded-lg font-condensed text-[10px] uppercase tracking-widest font-bold cursor-pointer transition-all duration-200 ${
                  typeFilter === 'ALL'
                    ? 'bg-[#00FF88]/10 border border-[#00FF88]/20 text-[#00FF88]'
                    : 'text-[#8B949E] hover:text-white border border-transparent'
                }`}
              >
                All
              </button>
              <button
                onClick={() => setTypeFilter('PUBLIC')}
                className={`px-3 py-1.5 rounded-lg font-condensed text-[10px] uppercase tracking-widest font-bold cursor-pointer transition-all duration-200 ${
                  typeFilter === 'PUBLIC'
                    ? 'bg-[#00FF88]/10 border border-[#00FF88]/20 text-[#00FF88]'
                    : 'text-[#8B949E] hover:text-white border border-transparent'
                }`}
              >
                Public
              </button>
              <button
                onClick={() => setTypeFilter('PRIVATE')}
                className={`px-3 py-1.5 rounded-lg font-condensed text-[10px] uppercase tracking-widest font-bold cursor-pointer transition-all duration-200 ${
                  typeFilter === 'PRIVATE'
                    ? 'bg-[#00FF88]/10 border border-[#00FF88]/20 text-[#00FF88]'
                    : 'text-[#8B949E] hover:text-white border border-transparent'
                }`}
              >
                Private
              </button>
            </div>
          </div>

          {error && (
            <div className="p-4 mb-6 rounded-xl bg-red-500/[0.04] border border-red-500/20 font-mono text-xs text-red-400">
              ⚠️ {error}
            </div>
          )}

          {/* Repository Filter search bar */}
          <div className="relative mb-5">
            <Search className="absolute left-4 top-1/2 -translate-y-1/2 text-[#484F58]" size={14} />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search workspaces and indexing tags..."
              className="w-full pl-11 pr-5 py-2.5 bg-white/[0.005] border border-white/[0.04] rounded-xl font-sans text-xs text-white outline-hidden focus:border-[#00FF88]/30 focus:shadow-[0_0_20px_rgba(0,255,136,0.03)] transition-all duration-300 shadow-inner"
            />
          </div>

          {/* Repos Grid layout */}
          {loading ? (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 py-4">
              {[1, 2, 4, 5].map(i => (
                <div key={i} className="animate-pulse bg-white/[0.01] border border-white/[0.03] rounded-2xl p-6 h-36">
                  <div className="h-4 bg-white/[0.04] rounded w-1/3 mb-4"></div>
                  <div className="h-3 bg-white/[0.04] rounded w-3/4 mb-2"></div>
                  <div className="h-3 bg-white/[0.04] rounded w-1/2"></div>
                </div>
              ))}
            </div>
          ) : filteredRepos.length === 0 ? (
            <div className="text-center py-20 border border-dashed border-white/[0.05] rounded-2xl bg-[#03060a]/30">
              <Code size={34} className="mx-auto text-[#484F58] mb-4 animate-pulse" />
              <h4 className="font-display text-sm font-bold text-white uppercase tracking-wider mb-2">No repositories found</h4>
              <p className="font-sans text-xs text-[#8B949E] max-w-sm mx-auto leading-relaxed">Try filtering by private/public, or enter a custom repository handle in the Ingestion terminal above.</p>
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {filteredRepos.map(repo => (
                <div
                  key={repo.id}
                  onClick={() => onSelectRepo(repo)}
                  className="group glass-card p-4 rounded-xl flex flex-col justify-between cursor-pointer transition-all duration-300 hover:border-white/[0.08] hover:scale-[1.01] shadow-xl hover:shadow-[0_20px_50px_rgba(0,0,0,0.6)]"
                >
                  <div className="space-y-2.5">
                    <div className="flex items-center justify-between gap-3">
                      <span className="font-display font-black text-sm tracking-widest text-white group-hover:text-[#00FF88] transition-colors truncate max-w-[75%] uppercase">
                        {repo.name}
                      </span>
                      <span className={`px-2.5 py-0.5 rounded-lg text-[9px] font-condensed font-bold tracking-widest uppercase border ${
                        repo.isPrivate
                          ? 'bg-[#FF8C00]/10 border-[#FF8C00]/25 text-[#FF8C00]'
                          : 'bg-white/[0.01] border-white/[0.05] text-[#8B949E]'
                      }`}>
                        {repo.isPrivate ? 'Private' : 'Public'}
                      </span>
                    </div>

                    <p className="font-sans text-[11px] text-[#8B949E] line-clamp-2 leading-relaxed min-h-[33px]">
                      {repo.description || 'No database profile notes provided for this repository asset.'}
                    </p>
                  </div>

                  <div className="flex items-center justify-between pt-2.5 border-t border-white/[0.03] mt-3.5 font-condensed text-[10px] text-[#484F58]">
                    <span className="font-condensed font-bold uppercase tracking-widest text-[#8B949E]/75">OWNER: {repo.owner}</span>
                    <span className="flex items-center gap-1.5 group-hover:text-[#00FF88] transition-colors font-display text-[10px] uppercase font-black tracking-widest">
                      ANALYZE
                      <ArrowRight size={10} className="transform group-hover:translate-x-1 transition-transform" />
                    </span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </>
      ) : (
        /* History logs Tab layout */
        <div className="space-y-4">
          <div className="flex justify-between items-center mb-4">
            <div>
              <h3 className="font-display text-base font-black text-white uppercase tracking-wider">VULNERABILITY INDEX LOGS</h3>
              <p className="font-condensed text-xs text-[#8B949E] uppercase tracking-[0.1em] mt-0.5">// Sync status: Active Pipeline trace history</p>
            </div>
            <button
              onClick={fetchHistory}
              disabled={loadingHistory}
              className="p-2 px-3 rounded-xl bg-white/[0.01] border border-white/[0.04] font-display text-[9px] font-black uppercase tracking-widest text-[#8B949E] hover:text-white cursor-pointer flex items-center gap-1.5 transition-colors shadow-inner"
            >
              <RefreshCw size={10} className={loadingHistory ? 'animate-spin' : ''} />
              Refresh
            </button>
          </div>

          {historyError && (
            <div className="p-4 rounded-xl bg-red-500/[0.04] border border-red-500/20 font-mono text-xs text-red-400">
              ⚠️ {historyError}
            </div>
          )}

          {loadingHistory ? (
            <div className="space-y-4">
              {[1, 2, 3].map(i => (
                <div key={i} className="animate-pulse bg-white/[0.01] border border-white/[0.03] rounded-2xl p-6 h-28"></div>
              ))}
            </div>
          ) : history.length === 0 ? (
            <div className="text-center py-20 border border-dashed border-white/[0.05] rounded-2xl bg-[#03060a]/30">
              <Database size={32} className="mx-auto text-[#484F58] mb-4 animate-pulse" />
              <h4 className="font-display text-sm font-bold text-white uppercase tracking-wider mb-2">No historical trace records</h4>
              <p className="font-sans text-xs text-[#8B949E] max-w-sm mx-auto leading-relaxed">Run clean and thorough conduits compiles to register team security reports database entries.</p>
            </div>
          ) : (
            <div className="space-y-2.5">
              {history.map(reportItem => {
                const grade = getGrade(reportItem.score);
                const dateText = new Date(reportItem.scannedAt).toLocaleString([], {
                  year: 'numeric', month: 'short', day: 'numeric',
                  hour: '2-digit', minute: '2-digit'
                });

                return (
                  <div
                    key={reportItem.id}
                    onClick={() => onSelectHistoricReport(reportItem)}
                    className="group glass-card p-3.5 flex flex-col md:flex-row md:items-center justify-between gap-3.5 cursor-pointer transition-all duration-300 rounded-xl hover:border-white/[0.08] hover:scale-[1.005] shadow-xl"
                  >
                    <div className="flex items-center gap-4">
                      {/* Premium Letter Grade badge */}
                      <div className={`w-11 h-11 rounded-xl bg-white/[0.01] border border-white/[0.04] flex flex-col items-center justify-center shadow-inner`}>
                        <span className={`font-sans text-lg font-black leading-none ${grade.color}`}>{grade.char}</span>
                        <span className="font-mono text-[8.5px] text-[#8B949E] uppercase leading-none font-bold mt-0.5">{reportItem.score}</span>
                      </div>

                      <div className="space-y-1">
                        <h4 className="font-condensed text-xs font-bold text-[#8B949E] uppercase tracking-wider group-hover:text-[#00FF88] transition-colors flex items-center gap-1.5">
                          {reportItem.repositoryOwner}/<span className="text-white font-display font-black text-sm tracking-widest uppercase">{reportItem.repositoryName}</span>
                        </h4>
                        <div className="flex flex-wrap items-center gap-x-3 gap-y-1 font-condensed text-[10px] uppercase font-bold tracking-wider text-[#8B949E]/70 text-[10px]">
                          <span className="flex items-center gap-1.5">
                            <Calendar size={11} strokeWidth={2} />
                            {dateText}
                          </span>
                          <span>·</span>
                          <span>{reportItem.totalFilesScanned} parsed files</span>
                          <span>·</span>
                          <span className="text-[#00FF88] opacity-80 font-black">// AST SECURED</span>
                        </div>
                      </div>
                    </div>

                    {/* Counts visual tag indicators */}
                    <div className="flex items-center justify-between md:justify-end gap-3.5 border-t md:border-t-0 border-white/[0.03] pt-2.5 md:pt-0">
                      <div className="flex items-center gap-1.5 font-condensed text-[9px] tracking-wider uppercase font-bold">
                        {reportItem.counts.critical > 0 && (
                          <span className="bg-[#FF4444]/10 border border-[#FF4444]/30 text-[#FF4444] px-2.5 py-0.5 rounded-lg">
                            C:{reportItem.counts.critical}
                          </span>
                        )}
                        {reportItem.counts.high > 0 && (
                          <span className="bg-[#FF8C00]/10 border border-[#FF8C00]/25 text-[#FF8C00] px-2.5 py-0.5 rounded-lg">
                            H:{reportItem.counts.high}
                          </span>
                        )}
                        {reportItem.counts.medium > 0 && (
                          <span className="bg-[#FFD700]/10 border border-[#FFD700]/20 text-[#FFD700] px-2.5 py-0.5 rounded-lg">
                            M:{reportItem.counts.medium}
                          </span>
                        )}
                        {reportItem.counts.low > 0 && (
                          <span className="bg-white/[0.01] border border-white/[0.05] text-[#8B949E] px-2.5 py-0.5 rounded-lg">
                            L:{reportItem.counts.low}
                          </span>
                        )}
                        {reportItem.findings.length === 0 && (
                          <span className="bg-[#00FF88]/10 border border-[#00FF88]/30 text-[#00FF88] px-2.5 py-0.5 rounded-lg tracking-wider font-extrabold pb-0.5">
                            ✓ SECURED
                          </span>
                        )}
                      </div>

                      <div className="flex items-center gap-1 text-[10px] font-display font-black uppercase tracking-widest text-[#8B949E] group-hover:text-white transition-colors">
                        Replay
                        <ChevronRight size={12} strokeWidth={2.5} className="transform group-hover:translate-x-1 transition-transform" />
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {activeTab === 'GITHUB' && (
        <GithubWorkflowView />
      )}
    </div>
  );
}
