import React, { useState, useEffect } from 'react';
import { 
  Github, 
  Plus, 
  GitPullRequest, 
  Terminal, 
  ShieldAlert, 
  CheckCircle, 
  Activity, 
  Copy, 
  Download, 
  ExternalLink, 
  Settings, 
  Cpu, 
  ShieldCheck, 
  AlertTriangle, 
  TrendingUp, 
  ArrowRight,
  RefreshCw,
  FileCode
} from 'lucide-react';
import { apiFetch } from '../utils/api';
import { SeverityType, ScanReport } from '../types';

interface DBRepositoryMetadata {
  id: string; // "owner/name"
  name: string;
  owner: string;
  defaultBranch: string;
  lastScan: string | null;
  latestGrade: string | null;
  latestScore: number | null;
  historicalTrend: { score: number; scannedAt: string; grade: string }[];
  userLogin: string;
}

interface PRAnalysisResult {
  success: boolean;
  repository: string;
  prNumber: number;
  sourceBranch: string;
  targetSha: string;
  baseReport: ScanReport;
  prReport: ScanReport;
  comparison: {
    baseScore: number;
    prScore: number;
    scoreDelta: number;
    newFindings: any[];
    resolvedFindings: any[];
    attackChainsIntroduced: any[];
    attackChainsRemoved: any[];
  };
  markdown: string;
}

export function GithubWorkflowView() {
  // Imported repositories states
  const [repositories, setRepositories] = useState<DBRepositoryMetadata[]>([]);
  const [loadingRepos, setLoadingRepos] = useState<boolean>(true);
  const [reposError, setReposError] = useState<string | null>(null);

  // Import Repo form
  const [githubUrl, setGithubUrl] = useState<string>('');
  const [defaultBranch, setDefaultBranch] = useState<string>('');
  const [importing, setImporting] = useState<boolean>(false);
  const [importMessage, setImportMessage] = useState<string | null>(null);
  const [importError, setImportError] = useState<string | null>(null);

  // Active Selected Repo details
  const [selectedRepo, setSelectedRepo] = useState<DBRepositoryMetadata | null>(null);

  // CI/CD config states
  const [failOnCritical, setFailOnCritical] = useState<boolean>(true);
  const [failBelowScore, setFailBelowScore] = useState<number>(80);
  const [warningOnly, setWarningOnly] = useState<boolean>(false);
  const [workflowYaml, setWorkflowYaml] = useState<string>('');
  const [loadingWorkflow, setLoadingWorkflow] = useState<boolean>(false);

  // PR Form states
  const [prUrl, setPrUrl] = useState<string>('');
  const [prNumber, setPrNumber] = useState<string>('');
  const [analyzingPr, setAnalyzingPr] = useState<boolean>(false);
  const [prError, setPrError] = useState<string | null>(null);
  const [prResult, setPrResult] = useState<PRAnalysisResult | null>(null);
  const [copiedText, setCopiedText] = useState<string | null>(null);
  const [activePrSubTab, setActivePrSubTab] = useState<'METRICS' | 'MARKDOWN'>('METRICS');

  // Load repositories on mount
  const fetchRepositories = async () => {
    setLoadingRepos(true);
    setReposError(null);
    try {
      const res = await apiFetch('/api/github/repositories');
      if (!res.ok) throw new Error('Failed to retrieve GitHub repository list from system logs.');
      const data = await res.json();
      setRepositories(data.repositories || []);
    } catch (err: any) {
      setReposError(err.message || 'Error occurred querying API logs.');
    } finally {
      setLoadingRepos(false);
    }
  };

  useEffect(() => {
    fetchRepositories();
  }, []);

  // Handle repository import & scan
  const handleImportSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!githubUrl.trim()) return;

    setImporting(true);
    setImportError(null);
    setImportMessage(null);

    try {
      const res = await apiFetch('/api/github/import', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          githubUrl: githubUrl.trim(),
          defaultBranch: defaultBranch.trim() || undefined
        })
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Repository validation or network timeout error during recursive tree import.');
      }

      if (data.code === 'EMPTY_REPO') {
        throw new Error(`Repository error: ${data.message || 'Repository is empty or branch has not been initialized.'} (Branch: ${data.branch})`);
      }

      setImportMessage(`🎉 Successfully ingested, scanned, and cataloged repository ${data.repository.id}.`);
      setGithubUrl('');
      setDefaultBranch('');
      await fetchRepositories();
      setSelectedRepo(data.repository);
    } catch (err: any) {
      setImportError(err.message || 'System error during background git parsing.');
    } finally {
      setImporting(false);
    }
  };

  // Generate CI/CD YAML configurations
  useEffect(() => {
    if (!selectedRepo) return;
    setLoadingWorkflow(true);
    apiFetch('/api/github/workflow', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ failOnCritical, failBelowScore, warningOnly })
    })
      .then(res => res.json())
      .then(data => {
        setWorkflowYaml(data.yaml);
      })
      .catch(err => {
        console.error('Workflow config failed', err);
      })
      .finally(() => {
        setLoadingWorkflow(false);
      });
  }, [selectedRepo, failOnCritical, failBelowScore, warningOnly]);

  // Handle comparative PR analysis
  const handlePrAnalysisSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!prUrl.trim() || !prNumber.trim()) {
      setPrError('Provide a target GitHub Repository URL and pull request number to sweep.');
      return;
    }

    setAnalyzingPr(true);
    setPrError(null);
    setPrResult(null);

    try {
      const res = await apiFetch('/api/github/pr-analysis', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          githubUrl: prUrl.trim(),
          prNumber: prNumber.trim()
        })
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'An error occurred during PR scanning comparison.');
      }

      if (data.code === 'EMPTY_REPO') {
        throw new Error(`Repository error: ${data.message || 'Repository is empty or branch has not been initialized.'} (Branch: ${data.branch})`);
      }

      setPrResult(data);
    } catch (err: any) {
      setPrError(err.message || 'Endpoint connection or validation error occurred.');
    } finally {
      setAnalyzingPr(false);
    }
  };

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopiedText(label);
    setTimeout(() => setCopiedText(null), 2500);
  };

  const downloadYamlFile = () => {
    const element = document.createElement("a");
    const file = new Blob([workflowYaml], { type: 'text/yaml' });
    element.href = URL.createObjectURL(file);
    element.download = "audicode-scan.yml";
    document.body.appendChild(element);
    element.click();
    document.body.removeChild(element);
  };

  return (
    <div className="space-y-12 animate-fade-in">
      
      {/* Dynamic Grid Layout containing Import vs Form */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        
        {/* Left Column: Repository Import Control Form */}
        <div className="lg:col-span-1 space-y-6">
          <div className="glass-card border border-white/[0.04] rounded-2xl p-6 bg-[#040608]/50">
            <div className="flex items-center gap-2 pb-4 mb-4 border-b border-white/[0.04]">
              <div className="p-2 rounded-lg bg-[#00FF88]/10 text-[#00FF88]">
                <Github size={18} />
              </div>
              <div>
                <h3 className="font-display text-[11px] font-black uppercase tracking-widest text-white leading-tight">REPOSITORY SWEEPER</h3>
                <p className="font-sans text-[10px] text-[#8B949E] leading-none">Import public GitHub URLs</p>
              </div>
            </div>

            <form onSubmit={handleImportSubmit} className="space-y-4">
              <div>
                <label className="block font-condensed text-[10px] text-[#8B949E] uppercase tracking-wider mb-2 font-bold">Github Repository URL</label>
                <input 
                  type="text"
                  required
                  placeholder="https://github.com/owner/repository"
                  value={githubUrl}
                  onChange={(e) => setGithubUrl(e.target.value)}
                  className="w-full bg-[#090b10] border border-white/[0.06] focus:border-[#00FF88]/30 outline-hidden rounded-xl py-3 px-4 font-tech text-xs text-white placeholder-[#383F47] transition-all"
                />
              </div>

              <div>
                <label className="block font-condensed text-[10px] text-[#8B949E] uppercase tracking-wider mb-2 font-bold">Target Branch (Optional)</label>
                <input 
                  type="text"
                  placeholder="e.g. main, dev, release-v1"
                  value={defaultBranch}
                  onChange={(e) => setDefaultBranch(e.target.value)}
                  className="w-full bg-[#090b10] border border-white/[0.06] focus:border-[#00FF88]/30 outline-hidden rounded-xl py-3 px-4 font-tech text-xs text-white placeholder-[#383F47] transition-all"
                />
                <span className="block text-[9px] text-[#8B949E] mt-1.5 leading-normal font-sans">// Default branch is automatically derived if omitted.</span>
              </div>

              {importError && (
                <div className="p-3.5 rounded-xl border border-red-500/10 bg-red-500/[0.02] text-red-400 font-mono text-[10px] leading-relaxed">
                  ⚠️ {importError}
                </div>
              )}

              {importMessage && (
                <div className="p-3.5 rounded-xl border border-emerald-500/10 bg-emerald-500/[0.02] text-emerald-400 font-mono text-[10px] leading-relaxed">
                  {importMessage}
                </div>
              )}

              <button
                type="submit"
                disabled={importing}
                className="w-full bg-gradient-to-r from-[#00FF88] to-[#00E575] disabled:from-gray-800 disabled:to-gray-900 text-black py-3.5 rounded-xl font-display text-[9.5px] uppercase font-black tracking-widest cursor-pointer hover:shadow-[0_0_20px_rgba(0,255,136,0.3)] transition-all flex items-center justify-center gap-2 select-none"
              >
                {importing ? (
                  <>
                    <RefreshCw className="animate-spin text-black" size={12} />
                    Cloning & Scanning...
                  </>
                ) : (
                  <>
                    <Plus size={12} strokeWidth={3} />
                    Secure Ingestion
                  </>
                )}
              </button>
            </form>
          </div>

          {/* Quick Setup instructions card */}
          <div className="glass-card border border-white/[0.04] rounded-2xl p-6 bg-[#040608]/50 space-y-3.5">
            <h4 className="font-display text-[10px] font-black uppercase tracking-widest text-white flex items-center gap-2">
              <TrendingUp className="text-[#00FF88]" size={14} />
              NATIVE PIPELINE PHASES
            </h4>
            <ul className="space-y-3 font-sans text-[11px] text-[#8B949E] list-none p-0 leading-relaxed">
              <li className="flex gap-2 items-start">
                <span className="w-1.5 h-1.5 rounded-full bg-[#00FF88] mt-1.5 flex-shrink-0 animate-pulse"></span>
                <span><strong>Secure Fetch:</strong> Downloads raw files securely inside system boundary memory pools without persisting full cloned disks.</span>
              </li>
              <li className="flex gap-2 items-start">
                <span className="w-1.5 h-1.5 rounded-full bg-[#00FF88] mt-1.5 flex-shrink-0"></span>
                <span><strong>AST Scanning:</strong> Multi-pass taint state mechanics locate unvalidated propagation pathways directly.</span>
              </li>
              <li className="flex gap-2 items-start">
                <span className="w-1.5 h-1.5 rounded-full bg-[#00FF88] mt-1.5 flex-shrink-0"></span>
                <span><strong>Badging:</strong> Public read-only shields endpoints render scorecards instantly across your READMEs.</span>
              </li>
            </ul>
          </div>
        </div>

        {/* Right Columns: Available Imported Projects List & Workspace Control */}
        <div className="lg:col-span-2 space-y-6">
          <div className="glass-card border border-white/[0.04] rounded-2xl p-6 bg-[#040608]/50 min-h-[300px] flex flex-col">
            <div className="flex justify-between items-center pb-4 mb-5 border-b border-white/[0.04]">
              <div className="flex items-center gap-2">
                <div className="p-2 rounded-lg bg-[#4D9EFF]/10 text-[#4D9EFF]">
                  <Activity size={18} />
                </div>
                <div>
                  <h3 className="font-display text-[11px] font-black uppercase tracking-widest text-white leading-tight">IMPORTED REPOSITORIES</h3>
                  <p className="font-sans text-[10px] text-[#8B949E] leading-none">Security grade scorecards & metadata profiles</p>
                </div>
              </div>

              <button 
                onClick={fetchRepositories}
                className="p-2 rounded-lg border border-white/[0.06] hover:bg-white/[0.02] text-[#8B949E] hover:text-white transition-all cursor-pointer"
                title="Refresh logs list"
              >
                <RefreshCw size={13} className={loadingRepos ? 'animate-spin' : ''} />
              </button>
            </div>

            {loadingRepos ? (
              <div className="flex-1 flex flex-col items-center justify-center py-12">
                <RefreshCw className="animate-spin text-[#00FF88] mb-3" size={20} />
                <span className="font-mono text-[10px] text-[#8B949E]">// Fetching synced repository metadata...</span>
              </div>
            ) : repositories.length === 0 ? (
              <div className="flex-1 flex flex-col items-center justify-center py-12 text-center max-w-sm mx-auto">
                <Github size={36} className="text-[#383F47] mb-3 animate-pulse" />
                <span className="font-display text-[11px] font-bold uppercase tracking-wider text-[#8B949E] mb-1">No repositories integrated</span>
                <span className="font-sans text-[11px] text-[#8B949E]/75 leading-relaxed">Accept a GitHub repository URL on the left panel to execute an ingestion and configure CI/CD and security badges.</span>
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 flex-1">
                {repositories.map((repo) => {
                  const isSelected = selectedRepo?.id === repo.id;
                  const grade = repo.latestGrade || 'F';
                  const gradeColor = 
                    grade.startsWith('A') ? 'text-[#00FF88] border-[#00FF88]/20 bg-[#00FF88]/5' :
                    grade.startsWith('B') ? 'text-[#4D9EFF] border-[#4D9EFF]/20 bg-[#4D9EFF]/5' :
                    grade.startsWith('C') ? 'text-[#FFD700] border-[#FFD700]/20 bg-[#FFD700]/5' :
                    grade.startsWith('D') ? 'text-[#FF8C00] border-[#FF8C00]/20 bg-[#FF8C00]/5' :
                    'text-[#FF4444] border-[#FF4444]/20 bg-[#FF4444]/5';

                  return (
                    <div 
                      key={repo.id}
                      onClick={() => setSelectedRepo(repo)}
                      className={`border p-4 rounded-xl cursor-pointer transition-all duration-200 flex flex-col justify-between ${
                        isSelected 
                          ? 'border-[#00FF88]/50 bg-[#00FF88]/[0.015] shadow-[0_4px_20px_rgba(0,255,136,0.03)]' 
                          : 'border-white/[0.04] bg-[#070b10]/40 hover:border-white/[0.1] hover:bg-white/[0.01]'
                      }`}
                    >
                      <div className="space-y-1">
                        <div className="flex justify-between items-start gap-3">
                          <h4 className="font-display text-[12px] font-black uppercase text-white tracking-wide truncate pr-4">{repo.name}</h4>
                          <span className={`px-2 py-0.5 rounded-md font-display text-[10px] font-black border ${gradeColor}`}>{grade}</span>
                        </div>
                        <p className="font-condensed text-[10px] text-[#8B949E] uppercase tracking-wider">@{repo.owner} · branch: {repo.defaultBranch}</p>
                      </div>

                      <div className="flex justify-between items-center mt-5 pt-3 border-t border-white/[0.03]">
                        <span className="font-sans text-[9px] text-[#8B949E]">
                          Last scan: {repo.lastScan ? new Date(repo.lastScan).toLocaleDateString() : 'Never'}
                        </span>
                        
                        {/* Mini Sparkline graph representations */}
                        <div className="flex items-end gap-1 px-1 py-0.5 roundedbg-white/[0.02] border border-white/[0.04]">
                          {repo.historicalTrend?.slice(-4).map((trend, tid) => {
                            const hRatio = Math.max(12, Math.min(28, (trend.score / 100) * 28));
                            return (
                              <div 
                                key={tid}
                                className="w-1.5 rounded-ts-xs rounded-te-xs bg-[#4D9EFF]"
                                style={{ height: `${hRatio}px` }}
                                title={`Scored ${trend.score}% on ${new Date(trend.scannedAt).toLocaleDateString()}`}
                              ></div>
                            );
                          })}
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Selected Repository Control Workspace - Yaml generator & Badge copy codes */}
      {selectedRepo && (
        <section className="glass-card border border-[#00FF88]/20 rounded-2xl overflow-hidden shadow-[0_20px_60px_rgba(0,255,136,0.01)] bg-[#03060a]/60 animate-fade-in p-6 md:p-8">
          <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 pb-6 mb-8 border-b border-white/[0.04]">
            <div>
              <span className="font-condensed text-[10px] text-[#00FF88] uppercase tracking-[0.2em] font-extrabold">// AUTOMATED WORKFLOW HUB</span>
              <h3 className="font-display text-lg font-black uppercase text-white tracking-widest mt-1">GATING & SECURITY COVERAGE // {selectedRepo.id}</h3>
            </div>
            
            <div className="flex items-center gap-3">
              <span className="font-sans text-xs text-[#8B949E]">Dynamic badge:</span>
              <img 
                src={`/api/github/badge/${selectedRepo.owner}/${selectedRepo.name}?t=${Date.now()}`} 
                alt="Security Status Badge" 
                className="h-5"
                referrerPolicy="no-referrer"
              />
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
            
            {/* CI/CD Gate Customizer Panel */}
            <div className="space-y-6">
              <h4 className="font-display text-[11px] font-black uppercase tracking-widest text-[#4D9EFF] flex items-center gap-2">
                <Settings size={14} />
                CI/CD ENFORCEMENT PARAMETERS
              </h4>

              <div className="space-y-4">
                {/* Checkbox: Fail on Critical */}
                <label className="flex items-center gap-3.5 p-4 rounded-xl border border-white/[0.04] bg-[#070b10]/40 transition-all hover:border-white/[0.08] cursor-pointer selection:bg-transparent">
                  <input 
                    type="checkbox"
                    checked={failOnCritical}
                    onChange={(e) => {
                      setFailOnCritical(e.target.checked);
                      if (e.target.checked) setWarningOnly(false);
                    }}
                    className="w-4 h-4 rounded-sm bg-[#090b10] border-white/[0.1] text-[#00FF88] focus:ring-0"
                  />
                  <div>
                    <span className="block font-display text-[11px] uppercase font-black tracking-wide text-white">Fail Build on Critical Findings</span>
                    <span className="block text-[10px] text-[#8B949E] mt-0.5 font-sans leading-normal">Instantly fail integration checks if SQL injections, remote code executions, or private crypto-keys are found.</span>
                  </div>
                </label>

                {/* Score threshold Slider */}
                <div className="p-4 rounded-xl border border-white/[0.04] bg-[#070b10]/40">
                  <div className="flex justify-between items-center mb-2.5">
                    <div>
                      <span className="block font-display text-[11px] uppercase font-black tracking-wide text-white">Security Score Lower Barrier</span>
                      <span className="block text-[10px] text-[#8B949E] mt-0.5 font-sans leading-normal">Build fails if overall codebase score drops below this metric.</span>
                    </div>
                    <span className="font-tech text-xs text-[#00FF88] font-bold bg-[#00FF88]/10 px-2 py-1 rounded-md">{failBelowScore}%</span>
                  </div>
                  <input 
                    type="range"
                    min="10"
                    max="100"
                    step="5"
                    value={failBelowScore}
                    onChange={(e) => {
                      setFailBelowScore(Number(e.target.value));
                      setWarningOnly(false);
                    }}
                    className="w-full accent-[#00FF88] bg-[#090b10] h-1.5 rounded-full cursor-pointer mt-1"
                  />
                </div>

                {/* Checkbox: Warning only */}
                <label className="flex items-center gap-3.5 p-4 rounded-xl border border-white/[0.04] bg-[#070b10]/40 transition-all hover:border-white/[0.08] cursor-pointer selection:bg-transparent">
                  <input 
                    type="checkbox"
                    checked={warningOnly}
                    onChange={(e) => {
                      setWarningOnly(e.target.checked);
                      if (e.target.checked) {
                        setFailOnCritical(false);
                      }
                    }}
                    className="w-4 h-4 rounded-sm bg-[#090b10] border-white/[0.1] text-[#00FF88] focus:ring-0"
                  />
                  <div>
                    <span className="block font-display text-[11px] uppercase font-black tracking-wide text-white">Warning-Only Compliance Mode</span>
                    <span className="block text-[10px] text-[#8B949E] mt-0.5 font-sans leading-normal">Allows passing status regardless of violations, printing scan warnings on workflow logs instead.</span>
                  </div>
                </label>
              </div>

              {/* Badging code snippet panel */}
              <div className="p-5 rounded-xl border border-[#4D9EFF]/10 bg-[#4D9EFF]/[0.01] space-y-3.5">
                <h5 className="font-display text-[10px] font-black uppercase text-[#4D9EFF] tracking-widest flex items-center gap-2">
                  <FileCode size={13} />
                  README EMBED INTEGRATION SINK
                </h5>
                <p className="font-sans text-[10px] text-[#8B949E] leading-normal">Display real-time security scorecards directly inside repo landing headers:</p>
                
                <div className="flex gap-2">
                  <input 
                    type="text"
                    readOnly
                    value={`[![AudiCode Security Badge](https://audicode-security.app/api/github/badge/${selectedRepo.owner}/${selectedRepo.name})](https://audicode-security.app)`}
                    className="flex-1 bg-[#090b10] border border-white/[0.06] rounded-xl font-mono text-[9.5px] py-2 px-3 text-[#E6EDF3] select-all outline-hidden"
                  />
                  <button
                    onClick={() => copyToClipboard(`[![AudiCode Security Badge](https://audicode-security.app/api/github/badge/${selectedRepo.owner}/${selectedRepo.name})](https://audicode-security.app)`, 'BADGE')}
                    className="px-3 border border-white/[0.06] bg-[#090b10] hover:bg-white/[0.02] text-[#8B949E] hover:text-white rounded-xl transition-all font-sans text-[10px] flex items-center justify-center cursor-pointer"
                  >
                    {copiedText === 'BADGE' ? 'Copied' : <Copy size={12} />}
                  </button>
                </div>
              </div>
            </div>

            {/* Workflow File display panel */}
            <div className="flex flex-col space-y-3">
              <div className="flex justify-between items-center">
                <h4 className="font-display text-[11px] font-black uppercase tracking-widest text-[#00FF88] flex items-center gap-2">
                  <FileCode size={14} />
                  .github/workflows/audicode-scan.yml
                </h4>

                <div className="flex gap-2">
                  <button
                    onClick={() => copyToClipboard(workflowYaml, 'YAML')}
                    className="p-2 border border-white/[0.06] hover:bg-white/[0.02] text-[#8B949E] hover:text-white rounded-lg transition-all font-sans text-[10px] flex items-center gap-1.5 cursor-pointer"
                  >
                    <Copy size={12} />
                    {copiedText === 'YAML' ? 'Copied!' : 'Copy'}
                  </button>
                  <button
                    onClick={downloadYamlFile}
                    className="p-2 border border-white/[0.06] hover:bg-[#00FF88]/10 hover:text-[#00FF88] rounded-lg transition-all font-sans text-[10px] flex items-center gap-1.5 cursor-pointer"
                  >
                    <Download size={12} />
                    Download
                  </button>
                </div>
              </div>

              <div className="flex-1 bg-[#090b10] border border-white/[0.06] rounded-xl p-4 overflow-auto scrollbar-thin max-h-[400px] font-mono text-[10.5px] leading-relaxed text-[#8B949E]">
                <pre className="whitespace-pre">{workflowYaml || 'Generating compiler pipeline scripts...'}</pre>
              </div>
            </div>
          </div>
        </section>
      )}

      {/* Pull Request Security Sweep Sandbox Analyzer Segment */}
      <section className="glass-card border border-white/[0.04] rounded-2xl p-6 md:p-10 bg-[#040608]/40 shadow-[0_24px_50px_rgba(0,0,0,0.5)]">
        <div className="flex items-center gap-2 pb-4 mb-6 border-b border-white/[0.04]">
          <div className="p-2.5 rounded-xl bg-[#00FF88]/10 text-[#00FF88]">
            <GitPullRequest size={20} />
          </div>
          <div>
            <span className="font-condensed text-[11px] text-[#00FF88] uppercase tracking-[0.2em] block font-extrabold">// COMPARATIVE DIFF ANALYZER</span>
            <h2 className="font-display text-xl font-black uppercase tracking-wider text-white">Pull Request Security Sweep</h2>
          </div>
        </div>

        <p className="font-sans text-xs text-[#8B949E] max-w-xl pb-1.5 leading-relaxed">
          Compare pull request modified assets against baseline branch metrics before staging integrations.
        </p>

        {/* PR input form */}
        <form onSubmit={handlePrAnalysisSubmit} className="grid grid-cols-1 md:grid-cols-3 gap-4 bg-[#070b10]/40 p-5 border border-white/[0.03] rounded-2xl max-w-4xl mt-4">
          <div className="md:col-span-2">
            <label className="block font-condensed text-[9px] text-[#8B949E] uppercase tracking-wider mb-2 font-black">// TARGET CODE REPOSITORY URL</label>
            <input 
              type="text"
              required
              placeholder="https://github.com/owner/repository"
              value={prUrl}
              onChange={(e) => setPrUrl(e.target.value)}
              className="w-full bg-[#090b10] border border-white/[0.06] focus:border-[#00FF88]/30 outline-hidden rounded-xl py-3 px-4 font-tech text-xs text-white"
            />
          </div>

          <div>
            <label className="block font-condensed text-[9px] text-[#8B949E] uppercase tracking-wider mb-2 font-black">// PR NUMBER</label>
            <div className="flex gap-2.5">
              <input 
                type="number"
                required
                min="1"
                placeholder="PR #, e.g. 14"
                value={prNumber}
                onChange={(e) => setPrNumber(e.target.value)}
                className="flex-1 bg-[#090b10] border border-white/[0.06] focus:border-[#00FF88]/30 outline-hidden rounded-xl py-3 px-4 font-tech text-xs text-white"
              />
              <button
                type="submit"
                disabled={analyzingPr}
                className="bg-gradient-to-r from-[#00FF88] to-[#00E575] disabled:from-gray-800 disabled:to-gray-900 text-black px-5 rounded-xl font-display text-[9.5px] uppercase font-black tracking-widest hover:shadow-[0_0_20px_rgba(0,255,136,0.2)] hover:scale-[1.02] active:scale-[0.98] transition-all flex items-center justify-center select-none cursor-pointer text-center"
              >
                {analyzingPr ? <RefreshCw className="animate-spin" size={12} /> : 'Scan PR'}
              </button>
            </div>
          </div>
        </form>

        {prError && (
          <div className="p-4 rounded-xl border border-red-500/10 bg-red-500/[0.02] text-red-400 font-mono text-[11px] max-w-4xl mt-5 leading-relaxed">
            ⚠️ Comparative trace aborted: {prError}
          </div>
        )}

        {analyzingPr && (
          <div className="py-16 text-center space-y-4 max-w-4xl mt-5 border border-dashed border-white/[0.04] bg-[#070b10]/20 rounded-2xl">
            <RefreshCw className="animate-spin text-[#00FF88] mx-auto" size={24} />
            <h4 className="font-display text-[11px] font-black uppercase text-white tracking-widest animate-pulse">Running Comparative AST Trace</h4>
            <p className="font-sans text-[11px] text-[#8B949E] max-w-sm mx-auto leading-relaxed">Downloading target pull request changed code files, establishing baseline, and virtually merging assets recursively...</p>
          </div>
        )}

        {/* PR Results layout segment */}
        {prResult && (
          <section className="mt-8 border border-white/[0.04] bg-[#070b10]/20 rounded-2xl overflow-hidden animate-fade-in">
            {/* Nav Row */}
            <div className="flex justify-between items-center bg-[#090b10] border-b border-white/[0.04] px-6 py-4">
              <div className="flex items-center gap-3">
                <span className="w-2.5 h-2.5 rounded-full bg-[#00FF88] animate-pulse"></span>
                <span className="font-display text-[10px] font-black uppercase tracking-widest text-[#E6EDF3] leading-none">PR AUDIT COMPLETE FOR #{prResult.prNumber}</span>
              </div>

              {/* Toggle Subtabs */}
              <div className="flex bg-[#03060a] border border-white/[0.04] rounded-lg p-1 font-sans text-[10px]">
                <button
                  onClick={() => setActivePrSubTab('METRICS')}
                  className={`px-3 py-1.5 rounded-md font-display text-[9px] font-black uppercase tracking-wider cursor-pointer transition-all duration-200 ${
                    activePrSubTab === 'METRICS'
                      ? 'bg-[#00FF88]/10 text-[#00FF88] border border-[#00FF88]/20'
                      : 'text-[#8B949E] hover:text-[#E6EDF3] border border-transparent'
                  }`}
                >
                  Visual Metrics
                </button>
                <button
                  onClick={() => setActivePrSubTab('MARKDOWN')}
                  className={`px-3 py-1.5 rounded-md font-display text-[9px] font-black uppercase tracking-wider cursor-pointer transition-all duration-200 ${
                    activePrSubTab === 'MARKDOWN'
                      ? 'bg-[#00FF88]/10 text-[#00FF88] border border-[#00FF88]/20'
                      : 'text-[#8B949E] hover:text-[#E6EDF3] border border-transparent'
                  }`}
                >
                  GitHub comment
                </button>
              </div>
            </div>

            {/* Sub-tab 1: Visual Metrics */}
            {activePrSubTab === 'METRICS' && (
              <div className="p-6 md:p-8 space-y-8 animate-fade-in">
                {/* Score delta showcase widgets */}
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                  <div className="bg-[#03060a]/40 border border-white/[0.03] p-5 rounded-2xl flex flex-col justify-between">
                    <span className="font-condensed text-[9px] text-[#8B949E] uppercase tracking-wider font-extrabold">// COMPLIANCE SCORE</span>
                    <div className="flex items-baseline gap-2 mt-4 mb-1">
                      <span className="font-display font-black text-3xl text-white tracking-widest">{prResult.comparison.prScore}%</span>
                      <span className={`font-mono text-xs font-bold px-1.5 py-0.5 rounded-md ${
                        prResult.comparison.scoreDelta > 0 ? 'text-[#00FF88] bg-[#00FF88]/5' : 
                        prResult.comparison.scoreDelta < 0 ? 'text-[#FF4444] bg-[#FF4444]/5' : 'text-[#8B949E] bg-white/[0.02]'
                      }`}>
                        {prResult.comparison.scoreDelta > 0 ? `+${prResult.comparison.scoreDelta}` : prResult.comparison.scoreDelta}
                      </span>
                    </div>
                    <span className="font-sans text-[10px] text-[#8B949E]">Baseline scoring: {prResult.comparison.baseScore}%</span>
                  </div>

                  <div className="bg-[#03060a]/40 border border-white/[0.03] p-5 rounded-2xl flex flex-col justify-between">
                    <span className="font-condensed text-[9px] text-[#8B949E] uppercase tracking-wider font-extrabold">// NEW VULNERABILITIES</span>
                    <span className={`block font-display font-black text-3xl mt-4 mb-1 tracking-widest ${prResult.comparison.newFindings.length > 0 ? 'text-[#FF4444]' : 'text-[#00FF88]'}`}>
                      {prResult.comparison.newFindings.length}
                    </span>
                    <span className="font-sans text-[10px] text-[#8B949E]">Added to PR file list</span>
                  </div>

                  <div className="bg-[#03060a]/40 border border-white/[0.03] p-5 rounded-2xl flex flex-col justify-between">
                    <span className="font-condensed text-[9px] text-[#8B949E] uppercase tracking-wider font-extrabold">// RESOLVED VULNERABILITIES</span>
                    <span className="block font-display font-black text-3xl text-[#4D9EFF] mt-4 mb-1 tracking-widest">
                      {prResult.comparison.resolvedFindings.length}
                    </span>
                    <span className="font-sans text-[10px] text-[#8B949E]">Remediated relative to base</span>
                  </div>
                </div>

                <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
                  {/* Left Col: New & Resolved Findings lists */}
                  <div className="space-y-6">
                    {/* New findings section */}
                    <div className="space-y-3">
                      <h4 className="font-display text-[11px] font-black uppercase text-red-400 tracking-wider flex items-center gap-2">
                        <ShieldAlert size={14} />
                        New Findings Introduced ({prResult.comparison.newFindings.length})
                      </h4>

                      {prResult.comparison.newFindings.length === 0 ? (
                        <div className="p-4 rounded-xl border border-emerald-500/10 bg-emerald-500/[0.02] text-emerald-400 flex items-center gap-2.5 font-sans text-[11px]">
                          <CheckCircle size={14} />
                          No new vulnerabilities or secrets introduced in this pull request!
                        </div>
                      ) : (
                        <div className="space-y-3 max-h-[250px] overflow-y-auto scrollbar-thin">
                          {prResult.comparison.newFindings.map((f: any) => (
                            <div key={f.id} className="p-4 rounded-xl border border-red-500/10 bg-red-500/[0.015] space-y-2">
                              <div className="flex justify-between items-start gap-4">
                                <h5 className="font-display text-[11px] font-black uppercase text-white tracking-wide truncate">{f.ruleName}</h5>
                                <span className="px-1.5 py-0.5 rounded-sm font-display text-[8.5px] font-black bg-red-500/10 text-red-400 border border-red-500/20">{f.severity}</span>
                              </div>
                              <p className="font-mono text-[9.5px] text-[#8B949E] leading-relaxed truncate">{f.filePath}:{f.startLine}</p>
                              <p className="font-sans text-[11px] text-[#8B949E] leading-relaxed line-clamp-2 pt-1">{f.description}</p>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>

                    {/* Resolved findings section */}
                    <div className="space-y-3">
                      <h4 className="font-display text-[11px] font-black uppercase text-[#4D9EFF] tracking-wider flex items-center gap-2">
                        <CheckCircle size={14} />
                        Resolved Findings ({prResult.comparison.resolvedFindings.length})
                      </h4>

                      {prResult.comparison.resolvedFindings.length === 0 ? (
                        <span className="block font-sans text-[11px] text-[#8B949E] italic">// No pre-existing baseline findings were resolved.</span>
                      ) : (
                        <div className="space-y-3 max-h-[180px] overflow-y-auto scrollbar-thin">
                          {prResult.comparison.resolvedFindings.map((f: any) => (
                            <div key={f.id} className="p-3.5 rounded-xl border border-emerald-500/10 bg-emerald-500/[0.015] flex gap-3 items-start">
                              <CheckCircle className="text-emerald-400 mt-0.5 flex-shrink-0" size={12} />
                              <div>
                                <h5 className="font-display text-[10.5px] font-black uppercase text-white tracking-wide leading-none">{f.ruleName}</h5>
                                <p className="font-mono text-[9px] text-[#8B949E] mt-1.5 leading-none">{f.filePath}:{f.startLine}</p>
                              </div>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Right Col: Attack Chains comparison details */}
                  <div className="space-y-6">
                    <div className="space-y-3">
                      <h4 className="font-display text-[11px] font-black uppercase text-[#FF8C00] tracking-wider flex items-center gap-2">
                        <GitPullRequest size={14} className="text-[#FF8C00]" />
                        Attack Pathways comparative Trace
                      </h4>

                      <div className="p-5 rounded-2xl border border-[#FF8C00]/10 bg-[#FF8C00]/[0.015] space-y-4">
                        <div className="grid grid-cols-2 gap-4">
                          <div className="bg-[#03060a]/65 border border-white/[0.03] p-4 rounded-xl text-center">
                            <span className="block font-display font-black text-lg text-white">{prResult.comparison.attackChainsIntroduced.length}</span>
                            <span className="font-condensed text-[9px] text-[#8B949E] uppercase tracking-wider font-extrabold mt-1">Chains Introduced</span>
                          </div>
                          <div className="bg-[#03060a]/65 border border-white/[0.03] p-4 rounded-xl text-center">
                            <span className="block font-display font-black text-lg text-[#00FF88]">{prResult.comparison.attackChainsRemoved.length}</span>
                            <span className="font-condensed text-[9px] text-[#8B949E] uppercase tracking-wider font-extrabold mt-1">Chains Eliminated</span>
                          </div>
                        </div>

                        {prResult.comparison.attackChainsIntroduced.length > 0 && (
                          <div className="space-y-3 pt-2">
                            <span className="block font-condensed text-[9px] text-red-400 uppercase tracking-widest font-black">🚨 ALERT: SEVERE PATHWAY INTRODUCED</span>
                            {prResult.comparison.attackChainsIntroduced.map((chain: any, idx) => (
                              <div key={idx} className="p-3.5 rounded-xl bg-red-500/5 border border-red-500/10 text-left">
                                <span className="block font-display text-[11px] font-black uppercase text-white">{chain.name}</span>
                                <span className="block font-sans text-[10.5px] text-[#8B949E] leading-normal mt-1">{chain.businessImpact}</span>
                              </div>
                            ))}
                          </div>
                        )}

                        {prResult.comparison.attackChainsIntroduced.length === 0 && (
                          <div className="p-3.5 rounded-xl bg-emerald-500/5 border border-emerald-500/10 flex items-center gap-2.5 font-sans text-[11px] text-emerald-400">
                            <CheckCircle size={14} />
                            PR changes introduce no critical asset attack chains!
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* Sub-tab 2: Complete Markdown Comments */}
            {activePrSubTab === 'MARKDOWN' && (
              <div className="p-6 md:p-8 space-y-4 animate-fade-in flex flex-col h-full justify-between">
                <div className="flex justify-between items-center bg-[#090b10] border-b border-white/[0.04] p-1.5 rounded-xl">
                  <span className="font-mono text-[10px] text-[#8B949E] px-3 font-semibold">// MARKDOWN CODE COMMENT FORMAT (GITHUB COMPLIANT)</span>
                  <button
                    onClick={() => copyToClipboard(prResult.markdown, 'PRMRK')}
                    className="p-2 bg-gradient-to-r from-[#00FF88] to-[#00E575] text-black font-display text-[9.5px] uppercase font-black tracking-widest rounded-lg flex items-center gap-1.5 transition-all hover:scale-[1.01] active:scale-[0.98] select-none cursor-pointer text-center"
                  >
                    <Copy size={11} strokeWidth={3} />
                    {copiedText === 'PRMRK' ? 'Copied comment!' : 'Copy markdown'}
                  </button>
                </div>

                <div className="bg-[#090b10] border border-white/[0.06] rounded-xl p-5 overflow-auto max-h-[400px] font-mono text-[11px] leading-relaxed text-[#8B949E] custom-scroller h-full max-w-full">
                  <pre className="whitespace-pre-wrap">{prResult.markdown}</pre>
                </div>
              </div>
            )}
          </section>
        )}
      </section>

    </div>
  );
}
