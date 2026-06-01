import React, { useState, useEffect } from 'react';
import { ShieldAlert, Terminal, RefreshCw, Cpu, Database, CheckSquare, Sparkles } from 'lucide-react';
import { LoginView } from './components/LoginView';
import { DashboardView } from './components/DashboardView';
import { ReportView } from './components/ReportView';
import { GitHubUser, Repository, ScanReport } from './types';
import { DEMO_FILES, DEMO_REPOSITORIES } from './utils/demoData';
import { runScan } from './scanner';
import { fetchRepositoryFiles } from './githubService';

type PageState = 'INITIAL_CHECK' | 'LOGIN' | 'DASHBOARD' | 'SCANNING' | 'REPORT';

const getLocalHistory = (): ScanReport[] => {
  try {
    const rawHistory = window.localStorage.getItem('audi_scans_history');
    return rawHistory ? JSON.parse(rawHistory) : [];
  } catch (err) {
    console.error('Failed to parse scan history:', err);
    return [];
  }
};

const saveLocalReport = (report: ScanReport) => {
  try {
    const current = getLocalHistory();
    const filtered = current.filter(r => r.id !== report.id);
    filtered.unshift(report);
    window.localStorage.setItem('audi_scans_history', JSON.stringify(filtered));
  } catch (err) {
    console.error('Failed to save report history:', err);
  }
};

export default function App() {
  const [page, setPage] = useState<PageState>('INITIAL_CHECK');
  const [user, setUser] = useState<GitHubUser | null>(null);
  const [selectedRepo, setSelectedRepo] = useState<Repository | null>(null);
  const [scanReport, setScanReport] = useState<ScanReport | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);

  // Reactive scanning progress states from browser scanning runs
  const [scanProgress, setScanProgress] = useState<{
    status: 'connecting' | 'indexing' | 'fetching' | 'scanning' | 'done' | 'error';
    filesDiscovered: number;
    filesScanned: number;
    currentFile: string;
    percentage: number;
  }>({
    status: 'connecting',
    filesDiscovered: 0,
    filesScanned: 0,
    currentFile: 'Establishing secure communication...',
    percentage: 5
  });

  const getStageFromStatus = (status: string) => {
    switch (status) {
      case 'connecting': return 0;
      case 'indexing': return 1;
      case 'fetching': return 2;
      case 'scanning': return 3;
      case 'done': return 4;
      default: return 0;
    }
  };

  const scanStages = [
    { label: 'Initializing Secure Pipeline', desc: 'Establishing token channels and parsing repository parameters...', icon: <Database className="text-[#00FF88]" size={16} /> },
    { label: 'Ingesting Directory Trees', desc: 'Recursively scanning branch directories, removing build artifacts, and loading files...', icon: <Database className="text-[#00FF88]" size={16} /> },
    { label: 'Retrieving Source Code Files', desc: 'Sequentially buffering and checking remote source files under 50KB limits...', icon: <Cpu className="text-[#00FF88]" size={16} /> },
    { label: 'Taint Propagation and Scanning Engine', desc: 'Tracing inputs through AST nodes to identify command/injection flaws...', icon: <Terminal className="text-[#00FF88]" size={16} /> }
  ];

  // Bootstrap session state in offline-first mode
  useEffect(() => {
    const savedSession = window.localStorage.getItem('audi_sb_user_session');
    if (savedSession) {
      try {
        const parsed = JSON.parse(savedSession);
        setUser(parsed);
        setPage('DASHBOARD');
      } catch (err) {
        setPage('LOGIN');
      }
    } else {
      setPage('LOGIN');
    }
  }, []);

  const handleLoginSuccess = (loggedInUser: GitHubUser) => {
    setUser(loggedInUser);
    setPage('DASHBOARD');
  };

  const handleLogout = async () => {
    window.localStorage.removeItem('audi_sb_access_token');
    window.localStorage.removeItem('audi_sb_provider_token');
    window.localStorage.removeItem('audi_sb_user_session');

    setUser(null);
    setSelectedRepo(null);
    setScanReport(null);
    setPage('LOGIN');
  };

  // Direct client-side AST engine trigger
  const triggerScan = async (repo: Repository) => {
    setSelectedRepo(repo);
    setPage('SCANNING');
    setScanError(null);
    setScanProgress({
      status: 'connecting',
      filesDiscovered: 0,
      filesScanned: 0,
      currentFile: 'Resolving default branch parameters...',
      percentage: 5
    });

    try {
      // Connect stage
      await new Promise(resolve => setTimeout(resolve, 400));
      setScanProgress(p => ({
        ...p,
        status: 'indexing',
        currentFile: 'Ignoring build output folders and searching file hierarchy...',
        percentage: 25
      }));
      await new Promise(resolve => setTimeout(resolve, 400));

      let files: { path: string; content: string }[] = [];

      // Fetch or ingest files
      if (repo.id.toString().startsWith('demo-')) {
        const demoId = repo.id;
        files = DEMO_FILES[demoId] || [];
        if (files.length === 0) {
          throw new Error('Sandbox codebase contains no preloaded validation files.');
        }
      } else {
        setScanProgress(p => ({
          ...p,
          status: 'fetching',
          currentFile: 'Retrieving files through the public GitHub REST channels...',
          percentage: 45
        }));
        
        const token = user?.accessToken || window.localStorage.getItem('audi_sb_provider_token') || '';
        files = await fetchRepositoryFiles(repo.owner, repo.name, repo.defaultBranch || 'main', token);
      }

      setScanProgress(p => ({
        ...p,
        status: 'scanning',
        filesDiscovered: files.length,
        currentFile: 'Rebuilding data-flow graphs and testing security sinks...',
        percentage: 75
      }));
      await new Promise(resolve => setTimeout(resolve, 500));

      if (files.length === 0) {
        throw new Error('EMPTY_REPO: No supported source files found under 50KB constraints.');
      }

      // Execute browser-side AST taint and secrets propagation scan
      const report = await runScan(files, files.length, (progressUpdate) => {
        // Can be fed into layout
      });

      // Augment report attributes
      report.id = `report-${Date.now()}`;
      report.repositoryId = repo.id;
      report.repositoryName = repo.name;
      report.repositoryOwner = repo.owner;
      report.scannedAt = new Date().toISOString();

      // Save report in local persistence
      saveLocalReport(report);

      setScanProgress({
        status: 'done',
        filesDiscovered: files.length,
        filesScanned: files.length,
        currentFile: 'Compilation completed. Synthesizing grade guidelines...',
        percentage: 100
      });

      setScanReport(report);
      setPage('REPORT');

    } catch (err: any) {
      console.error('Scan failed:', err);
      if (err.message && err.message.includes('EMPTY_REPO')) {
        setScanError(`EMPTY_REPO: No supported files available in this branch.`);
      } else {
        setScanError(err.message || 'Analysis pipeline fault occurred while tracing source vectors.');
      }
    }
  };

  const handleSelectHistoricReport = (report: ScanReport) => {
    const repo: Repository = {
      id: report.repositoryId,
      name: report.repositoryName,
      owner: report.repositoryOwner,
      description: 'Historical scan session accessed from database.',
      isPrivate: false,
      defaultBranch: 'main',
      url: `https://github.com/${report.repositoryOwner}/${report.repositoryName}`
    };
    setSelectedRepo(repo);
    setScanReport(report);
    setPage('REPORT');
  };

  return (
    <div className="min-h-screen bg-transparent flex flex-col relative">
      
      {/* Universal Top Nav Indicator with glowing status */}
      <nav className="border-b border-white/[0.04] h-16 flex items-center justify-between px-6 bg-[#05070a]/40 backdrop-blur-xl sticky top-0 z-40 w-full">
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
            <span className="font-orbitron font-extrabold text-xl md:text-2xl text-white tracking-[0.02em]">
              Audi<span className="text-[#00FF88]">Code</span>
            </span>
          </div>

          <div className="flex items-center gap-2.5 px-3 py-1 rounded-full bg-white/[0.02] border border-white/[0.04]">
            <span className="w-1.5 h-1.5 rounded-full bg-[#00FF88] shadow-[0_0_8px_#00FF88]"></span>
            <span className="font-mono text-[9px] text-[#8B949E] uppercase tracking-widest font-semibold">Active Pipeline</span>
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
            onSelectRepo={triggerScan}
            onSelectHistoricReport={handleSelectHistoricReport}
          />
        )}

        {page === 'SCANNING' && selectedRepo && (
          <div className="flex-1 flex flex-col items-center justify-center px-4 max-w-xl mx-auto py-12 animate-fade-in min-h-[60vh] w-full">
            
            {scanError ? (
              scanError.startsWith('EMPTY_REPO:') ? (
                <div className="glass-card border border-[#00FF88]/20 p-8 rounded-2xl text-center w-full shadow-2xl">
                  <Terminal className="text-[#00FF88] mx-auto mb-4 animate-pulse" size={36} />
                  <h3 className="font-display text-sm font-black text-white uppercase tracking-wider mb-2">Repository is Empty</h3>
                  <p className="font-sans text-xs text-[#8B949E] leading-relaxed mb-6">
                    No commits or source files were found in this repository. 
                    <br /><br />
                    Please push your first commit and rescan.
                  </p>
                  <div className="flex gap-3 justify-center">
                    <button
                      onClick={() => {
                        setSelectedRepo(null);
                        setPage('DASHBOARD');
                      }}
                      className="px-5 py-2.5 rounded-xl bg-white/[0.01] border border-white/[0.06] hover:bg-white/[0.04] text-[#E6EDF3] font-display text-[10px] uppercase font-black tracking-widest cursor-pointer transition-all"
                    >
                      Dashboard
                    </button>
                    <button
                      onClick={() => triggerScan(selectedRepo)}
                      className="px-5 py-2.5 rounded-xl bg-gradient-to-r from-[#00FF88] to-[#00E575] text-black font-display text-[10px] uppercase font-black tracking-widest cursor-pointer hover:shadow-[0_0_20px_rgba(0,255,136,0.25)] transition-all"
                    >
                      Retry Ingestion
                    </button>
                  </div>
                </div>
              ) : (
                <div className="glass-card border border-red-500/20 p-8 rounded-2xl text-center w-full shadow-2xl">
                  <ShieldAlert className="text-red-400 mx-auto mb-4 animate-bounce" size={36} />
                  <h3 className="font-display text-sm font-black text-white uppercase tracking-wider mb-2">ANALYSIS PIPELINE FAULT</h3>
                  <p className="font-mono text-xs text-[#8B949E] leading-relaxed mb-6">{scanError}</p>
                  <div className="flex gap-3 justify-center">
                    <button
                      onClick={() => {
                        setSelectedRepo(null);
                        setPage('DASHBOARD');
                      }}
                      className="px-5 py-2.5 rounded-xl bg-white/[0.01] border border-white/[0.06] hover:bg-white/[0.04] text-[#E6EDF3] font-display text-[10px] uppercase font-black tracking-widest cursor-pointer transition-all"
                    >
                      Dashboard
                    </button>
                    <button
                      onClick={() => triggerScan(selectedRepo)}
                      className="px-5 py-2.5 rounded-xl bg-gradient-to-r from-[#00FF88] to-[#00E575] text-black font-display text-[10px] uppercase font-black tracking-widest cursor-pointer hover:shadow-[0_0_20px_rgba(0,255,136,0.25)] transition-all"
                    >
                      Retry Ingestion
                    </button>
                  </div>
                </div>
              )
            ) : (
              <div className="w-full text-center space-y-8">
                <div>
                  {/* Loader animation details */}
                  <div className="relative w-20 h-20 mx-auto mb-6 flex items-center justify-center">
                    <div className="absolute inset-0 border-[3px] border-[#00FF88]/10 rounded-full"></div>
                    <div className="absolute inset-0 border-[3px] border-[#00FF88] border-t-transparent rounded-full animate-spin"></div>
                    <div className="absolute inset-3 bg-gradient-to-tr from-[#00FF88]/5 to-transparent rounded-full animate-pulse"></div>
                    <Terminal size={22} className="text-[#00FF88] relative z-10" />
                  </div>

                  <span className="font-condensed text-[10px] text-[#00FF88] uppercase tracking-[0.25em] font-black px-4 py-1.5 rounded-xl bg-[#00FF88]/[0.02] border border-[#00FF88]/30 shadow-[0_0_15px_rgba(0,255,136,0.03)]">// SECURE PIPELINE INTEGRATOR</span>
                  <h3 className="font-display text-2xl font-black text-white uppercase tracking-wider leading-none mt-5 mb-1.5">
                    Analyzing {selectedRepo.name}
                  </h3>
                  <p className="font-condensed text-xs text-[#8B949E] uppercase tracking-widest font-bold">@{selectedRepo.owner} · compiling AST flow graphs</p>
                </div>

                {/* Progress bar visual container */}
                <div className="glass-card rounded-2xl p-6 shadow-3xl text-left space-y-5 border border-white/[0.03]">
                  <div>
                    <div className="flex justify-between items-center mb-2.5">
                      <span className="font-display text-[10px] text-white/95 font-black uppercase tracking-wider">Compilation Progress</span>
                      <span className="font-tech text-xs text-[#00FF88] font-bold">{scanProgress.percentage}%</span>
                    </div>
                    <div className="w-full bg-[#0B0F13] h-2 rounded-full overflow-hidden border border-white/[0.03]">
                      <div 
                        className="bg-gradient-to-r from-[#00FF88] to-[#00E575] h-full rounded-full transition-all duration-300 shadow-[0_0_8px_#00FF88]"
                        style={{ width: `${scanProgress.percentage}%` }}
                      ></div>
                    </div>
                  </div>

                  {/* Quantitative Stats boxes */}
                  <div className="grid grid-cols-2 gap-4">
                    <div className="bg-[#03060a]/50 border border-white/[0.03] rounded-xl p-4 text-center">
                      <span className="block font-display font-black text-xl text-white tracking-widest">
                        {scanProgress.filesDiscovered}
                      </span>
                      <span className="font-condensed text-[9px] text-[#8B949E] uppercase tracking-widest font-extrabold">Files Discovered</span>
                    </div>
                    <div className="bg-[#03060a]/50 border border-white/[0.03] rounded-xl p-4 text-center">
                      <span className="block font-display font-black text-xl text-white tracking-widest">
                        {scanProgress.filesScanned}
                      </span>
                      <span className="font-condensed text-[9px] text-[#8B949E] uppercase tracking-widest font-extrabold">Parsed AST Nodes</span>
                    </div>
                  </div>

                  {/* Active node scroll indicator */}
                  <div className="space-y-1.5 rounded-xl bg-[#030508]/60 border border-white/[0.03] p-4 text-left">
                    <span className="block font-condensed text-[9px] text-[#8B949E] uppercase tracking-[0.16em] font-bold">Active AST Scope Stream</span>
                    <div className="font-tech text-[10px] text-[#00FF88] truncate select-all leading-none py-0.5">
                      <span className="text-[#8B949E] mr-2 select-none">$</span>
                      {scanProgress.currentFile || 'Buffering semantic scope thread...'}
                    </div>
                  </div>
                </div>

                {/* Progress Steps Status display */}
                <div className="glass-card rounded-2xl p-6 text-left space-y-4 shadow-3xl border border-white/[0.03]">
                  {scanStages.map((stage, idx) => {
                    const stageIndex = getStageFromStatus(scanProgress.status);
                    const isActive = idx === stageIndex;
                    const isCompleted = idx < stageIndex;
                    
                    return (
                      <div
                        key={idx}
                        className={`flex items-start gap-4 transition-opacity duration-300 ${
                          isActive ? 'opacity-100' : isCompleted ? 'opacity-55' : 'opacity-15'
                        }`}
                      >
                        <div className="mt-0.5 flex-shrink-0">
                          {isCompleted ? (
                            <span className="w-4 h-4 rounded-full bg-[#00FF88]/10 border border-[#00FF88]/40 flex items-center justify-center font-mono text-[9px] text-[#00FF88] font-bold">✓</span>
                          ) : isActive ? (
                            <span className="w-4 h-4 rounded-full border border-[#00FF88] flex items-center justify-center relative">
                              <span className="absolute w-1.5 h-1.5 rounded-full bg-[#00FF88] animate-ping"></span>
                              <span className="w-1.5 h-1.5 rounded-full bg-[#00FF88]"></span>
                            </span>
                          ) : (
                            <span className="w-4 h-4 rounded-full border border-white/[0.08] bg-white/[0.01] flex items-center justify-center font-mono text-[9px] text-[#8B949E]">{idx + 1}</span>
                          )}
                        </div>

                        <div>
                          <h4 className={`font-display text-[11px] font-black uppercase tracking-widest leading-none ${isActive ? 'text-[#00FF88]' : isCompleted ? 'text-white' : 'text-[#8B949E]'}`}>
                            {stage.label}
                          </h4>
                          {isActive && (
                            <p className="font-sans text-[11px] text-[#8B949E]/90 mt-2 leading-relaxed">
                              {stage.desc}
                            </p>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

          </div>
        )}

        {page === 'REPORT' && scanReport && selectedRepo && (
          <ReportView
            report={scanReport}
            onGoBack={() => { setSelectedRepo(null); setScanReport(null); setPage('DASHBOARD'); }}
            onReScan={() => triggerScan(selectedRepo)}
            isReScanning={page === 'SCANNING'}
          />
        )}
      </main>

      {/* Footer copyright indicators */}
      <footer className="border-t border-[#21262D]/40 py-6 text-center text-[10px] text-[#8B949E] font-sans">
        <div className="font-bold uppercase tracking-wider text-[#C9D1D9]">AudiCode Security Report</div>
        <div className="text-[#484F58] mt-1 font-mono text-[9px]">
          GENERATED ON {scanReport?.scannedAt ? new Date(scanReport.scannedAt).toLocaleDateString(undefined, { year: 'numeric', month: 'long', day: 'numeric' }).toUpperCase() : new Date().toLocaleDateString(undefined, { year: 'numeric', month: 'long', day: 'numeric' }).toUpperCase()}
        </div>
      </footer>
    </div>
  );
}
