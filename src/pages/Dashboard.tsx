import { useEffect, useState, useRef, useCallback } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { User } from "@supabase/supabase-js";
import { signOut, getCurrentUser, supabase } from "../lib/supabase";
import HeroInput from "../components/HeroInput";
import { mockAuditResult } from "../data/mockData";
import ScoreRing from "../components/ScoreRing";
import SeverityPill from "../components/SeverityPill";
import VulnerabilityCard from "../components/VulnerabilityCard";
import CreditsBar from "../components/CreditsBar";
import { Severity } from "../types/audit";
import { Loader2, FolderSearch, ChevronDown, ChevronRight, AlertCircle, CheckCircle } from "lucide-react";
import { toast } from "@/components/ui/sonner";

interface JobStatus {
  id: string;
  status: "queued" | "running" | "completed" | "failed";
  progress: number;
  score?: number;
  grade?: string;
  confidence?: number;
  files_scanned?: number;
  error?: string;
  vulnerabilities?: any[];
}

const Dashboard = () => {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const [user, setUser] = useState<User | null>(null);

  useEffect(() => {
    // Check for OAuth token in URL hash and set session
    const hash = window.location.hash;
    if (hash && hash.includes("access_token")) {
      const params = new URLSearchParams(hash.substring(1));
      const accessToken = params.get("access_token");
      const refreshToken = params.get("refresh_token");
      if (accessToken) {
        supabase.auth.setSession({
          access_token: accessToken,
          refresh_token: refreshToken || "",
        }).then(() => {
          window.location.hash = "";
          getCurrentUser().then(setUser);
        });
      }
    }
  }, []);
  const [repoInfo, setRepoInfo] = useState<any>(null);
  const [hasAudited, setHasAudited] = useState(false);
  const [showRepos, setShowRepos] = useState(false);
  const [userRepos, setUserRepos] = useState<any[]>([]);
  const [loadingRepos, setLoadingRepos] = useState(false);
  const [analyzingRepo, setAnalyzingRepo] = useState<string | null>(null);
  const [jobStatus, setJobStatus] = useState<JobStatus | null>(null);
  const [currentJobId, setCurrentJobId] = useState<string | null>(null);
  const [authProvider, setAuthProvider] = useState<string | null>(null);
  const inputRef = useRef<HTMLDivElement>(null);
  const pollingRef = useRef<number | null>(null);
  const startTimeRef = useRef<number>(0);
  
  const isGitHubUser = authProvider === "github";

  // Poll for job status - separate function to avoid stale closure
  const pollJobStatus = useCallback(async (jobId: string, repoName: string) => {
    const elapsed = Date.now() - startTimeRef.current;
    const maxTime = 120000; // 2 minutes max

    try {
      const response = await fetch("/api/jobs", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ jobId }),
      });

      if (!response.ok) {
        if (response.status === 404) {
          clearInterval(pollingRef.current || 0);
          pollingRef.current = null;
          setAnalyzingRepo(null);
          toast.error("Scan failed: Job not found. Please try again.");
        }
        return;
      }

      const job: JobStatus = await response.json();
      setJobStatus(job);

      // Timeout check
      if (elapsed > maxTime) {
        clearInterval(pollingRef.current || 0);
        pollingRef.current = null;
        setAnalyzingRepo(null);
        toast.error("Scan timed out. The repository may be too large. Try a smaller repo.");
        return;
      }

      if (job.status === "completed" || job.status === "failed") {
        clearInterval(pollingRef.current || 0);
        pollingRef.current = null;
        
        if (job.status === "completed") {
          const mappedVulns = (job.vulnerabilities || []).map((v: any) => ({
            ...v,
            badCode: v.code || "",
            fixedCode: v.fix || "",
          }));
          
          const finalResult = {
            ...job,
            repo: { name: repoName },
            scan: {
              score: job.score,
              grade: job.grade,
              vulnerabilities: mappedVulns,
              confidence: job.confidence,
              files_scanned: job.files_scanned,
            },
          };
          
          setRepoInfo(finalResult);
          setHasAudited(true);
          const elapsed = ((Date.now() - startTimeRef.current) / 1000).toFixed(1);
          toast.success(`Scan completed in ${elapsed}s! Found ${finalResult.scan?.vulnerabilities?.length || 0} issues.`);
          sessionStorage.setItem("auditRepo", JSON.stringify(finalResult));
        } else if (job.status === "failed") {
          setAnalyzingRepo(null);
          toast.error(`Scan failed: ${job.error || "Unknown error. Please try again."}`);
        }
        
        setAnalyzingRepo(null);
        
        setTimeout(() => {
          document.getElementById("results")?.scrollIntoView({ behavior: "smooth" });
        }, 300);
      }
    } catch (err) {
      console.error("Polling error:", err);
    }
  }, []);

  // Auto-audit from URL if provided
  useEffect(() => {
    const doAutoAudit = async (repoUrl: string) => {
      setAnalyzingRepo(repoUrl);
      try {
        const { data: { session } } = await supabase.auth.getSession();
        const token = session?.provider_token || session?.access_token;
        const userId = session?.user?.id;
        
        // Use async jobs API
        const response = await fetch("/api/jobs", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ 
            repoUrl, 
            token: token || undefined,
            userId: userId || undefined,
          }),
        });
        
        if (response.ok) {
          const result = await response.json();
          console.log("Job created:", result);
          
          if (result.jobId) {
            setCurrentJobId(result.jobId);
            setJobStatus({ id: result.jobId, status: "queued", progress: 0 });
            startTimeRef.current = Date.now();
            
            const repoName = repoUrl.replace(/https?:\/\/github\.com\//, "");
            pollingRef.current = window.setInterval(() => {
              pollJobStatus(result.jobId, repoName);
            }, 2000);
          } else {
            console.error("No jobId in response:", result);
            setAnalyzingRepo(null);
          }
        } else {
          console.error("Failed to create job:", response.status, response.statusText);
          setAnalyzingRepo(null);
          toast.error(`Failed to start scan: ${response.statusText}`);
        }
      } catch (err) {
        console.error("Auto-audit failed:", err);
        setAnalyzingRepo(null);
      }
    };

    const initUser = async () => {
      const currentUser = await getCurrentUser();
      if (currentUser) {
        setUser(currentUser);
        
        // Get provider from session metadata
        const { data: { session } } = await supabase.auth.getSession();
        const provider = session?.user?.app_metadata?.provider || session?.user?.user_metadata?.provider || null;
        setAuthProvider(provider || "google");
        console.log("Provider:", provider);
        
        // Clear previous data if different user
        const storedUser = sessionStorage.getItem("current_user_id");
        if (storedUser !== currentUser.id) {
          sessionStorage.removeItem("auditRepo");
          sessionStorage.removeItem("github_repos");
          setRepoInfo(null);
          setHasAudited(false);
        }
        sessionStorage.setItem("current_user_id", currentUser.id);
        
        // Check for audit URL in query params
        const auditUrl = searchParams.get("audit");
        if (auditUrl) {
          doAutoAudit(auditUrl);
        }
        
        // Check for previous audit
        const stored = sessionStorage.getItem("auditRepo");
        if (stored) {
          try {
            setRepoInfo(JSON.parse(stored));
            setHasAudited(true);
          } catch (e) {
            sessionStorage.removeItem("auditRepo");
          }
        }
      }
    };
    initUser();
  }, [navigate, searchParams]);

  // Scroll to input after login
  useEffect(() => {
    if (user && inputRef.current) {
      const timer = setTimeout(() => {
        inputRef.current?.scrollIntoView({ behavior: "smooth", block: "center" });
      }, 300);
      return () => clearTimeout(timer);
    }
  }, [user]);

  // Cleanup polling on unmount
  useEffect(() => {
    return () => {
      if (pollingRef.current) {
        clearInterval(pollingRef.current);
      }
    };
  }, []);

  const handleSignOut = useCallback(async () => {
    await signOut();
    sessionStorage.removeItem("auditRepo");
    navigate("/");
  }, [navigate]);

  const fetchUserRepos = useCallback(async () => {
    // Toggle if already loaded
    if (userRepos.length > 0) {
      setShowRepos(prev => !prev);
      return;
    }
    
    setLoadingRepos(true);
    setShowRepos(true);
    
    try {
      // Get session to check for GitHub provider token
      const { data: { session } } = await supabase.auth.getSession();
      if (!session) {
        console.error("No session");
        setLoadingRepos(false);
        return;
      }

      // For GitHub OAuth, use provider_token if available, otherwise access_token won't work with GitHub API
      const token = session.provider_token || session.access_token;
      
      // If no GitHub token, need to ask user to sign in with GitHub for repo access
      if (!token) {
        console.warn("No GitHub token - user may have signed up with email");
        setUserRepos([]);
        setLoadingRepos(false);
        return;
      }

      const response = await fetch("https://api.github.com/user/repos?per_page=50&sort=updated", {
        headers: {
          Authorization: `Bearer ${token}`,
          Accept: "application/vnd.github.v3+json",
        },
      });
      
      if (response.ok) {
        const repos = await response.json();
        setUserRepos(repos || []);
      } else {
        setUserRepos([]);
      }
    } catch (err) {
      console.error("Error fetching repos:", err);
      setUserRepos([]);
    }
    
    setLoadingRepos(false);
  }, [userRepos.length]);

  const analyzeRepo = useCallback(async (repo: any) => {
    if (!repo || analyzingRepo) return;
    
    const repoUrl = repo.html_url || repo.full_name;
    const repoName = repo.full_name || `${repo.owner?.login}/${repo.name}`;
    setAnalyzingRepo(repoName);
    setShowRepos(false);
    
    try {
      const { data: { session } } = await supabase.auth.getSession();
      const token = session?.provider_token;
      const userId = session?.user?.id;
      
      const response = await fetch("/api/jobs", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ 
          repoUrl, 
          token: token || undefined,
          userId: userId || undefined,
        }),
      });
      
      if (response.ok) {
        const result = await response.json();
        
        if (result.jobId) {
          setCurrentJobId(result.jobId);
          setJobStatus({ id: result.jobId, status: "queued", progress: 0 });
          startTimeRef.current = Date.now();
          
          pollingRef.current = window.setInterval(() => {
            pollJobStatus(result.jobId, repoName);
          }, 2000);
        } else {
          console.error("No jobId in response:", result);
          setAnalyzingRepo(null);
          toast.error("Failed to start scan. Please try again.");
        }
      } else {
        console.error("Failed to create scan job:", response.status);
        setAnalyzingRepo(null);
        toast.error(`Failed to start scan: ${response.statusText}`);
      }
    } catch (err) {
      console.error("Error analyzing repo:", err);
      setAnalyzingRepo(null);
      toast.error("Failed to analyze repo. Please try again.");
    }
  }, [analyzingRepo, user, pollJobStatus]);

  const scoreData = repoInfo?.scan || repoInfo || mockAuditResult;

  // Build compatible data object
  const data = {
    vulnerabilities: scoreData.vulnerabilities || [],
    score: scoreData.score || 0,
    grade: scoreData.grade || "F",
  };

  if (!user) {
    return (
      <div className="min-h-screen pt-[80px] pb-20 px-6 md:px-10 flex items-center justify-center">
        <Loader2 className="w-6 h-6 text-primary animate-spin" />
      </div>
    );
  }

  return (
    <>
      {/* Hero Section */}
      <section className="min-h-screen flex flex-col items-center justify-center px-6 md:px-10 pt-[120px] pb-10 relative text-center overflow-hidden">
        {/* Grid Background */}
        <div
          className="absolute inset-0 opacity-40 pointer-events-none"
          style={{
            backgroundImage: "linear-gradient(hsl(var(--border))) 1px, transparent 1px), linear-gradient(90deg, hsl(var(--border)) 1px, transparent 1px)",
            backgroundSize: "40px 40px",
            maskImage: "radial-gradient(ellipse 80% 60% at 50% 50%, black 30%, transparent 100%)",
            WebkitMaskImage: "radial-gradient(ellipse 80% 60% at 50% 50%, black 30%, transparent 100%)",
          }}
        />

        {/* Glow */}
        <div className="absolute top-[30%] left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[300px] bg-[radial-gradient(ellipse,_hsl(var(--primary)/0.06)_0%,_transparent_70%)] pointer-events-none" />

        {/* Badge */}
        <div className="relative z-10 inline-flex items-center gap-2 px-3.5 py-1.5 bg-primary/10 border border-primary/20 rounded-full font-mono text-[11px] text-primary mb-8">
          <div className="w-1.5 h-1.5 bg-primary rounded-full animate-pulse" />
          AI-powered security analysis
        </div>

        {/* Heading */}
        <h1 className="relative z-10 text-5xl sm:text-7xl md:text-8xl lg:text-[96px] font-extrabold leading-[0.95] tracking-tighter">
          Your code.
          <br />
          <span className="text-primary">Exposed.</span>
          <br />
          <span className="text-muted-foreground">Then fixed.</span>
        </h1>

        {/* Subtitle */}
        <p className="relative z-10 mt-6 font-mono text-sm text-muted-foreground max-w-[480px] leading-relaxed">
          Paste a GitHub repo URL or select from your repos.
        </p>

        {/* Input Container */}
        <div ref={inputRef} className="relative z-10 mt-12 w-full flex flex-col items-center gap-4">
          {/* Main Input */}
          <div className="w-full max-w-[560px]">
            <HeroInput />
          </div>
          
          {/* Repo Access Button */}
          <button
            onClick={isGitHubUser ? fetchUserRepos : () => window.open("https://github.com", "_blank")}
            disabled={loadingRepos}
            className="flex items-center gap-2 px-4 py-2 font-mono text-sm text-muted-foreground hover:text-foreground transition-colors"
          >
            {loadingRepos ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : showRepos ? (
              <ChevronDown className="w-4 h-4" />
            ) : (
              <ChevronRight className="w-4 h-4" />
            )}
            <FolderSearch className="w-4 h-4" />
            {isGitHubUser ? "My GitHub Repos" : "Browse Public Repos"}
          </button>

          {/* User Repos Dropdown */}
          {showRepos && (
            <div className="w-full max-w-[560px] bg-surface border border-border rounded-lg overflow-hidden">
              {userRepos.length === 0 ? (
                <div className="p-4 text-sm text-muted-foreground text-center">
                  {loadingRepos ? "Loading..." : "No repositories found."}
                </div>
              ) : (
                <div className="max-h-[250px] overflow-y-auto">
                  {userRepos.map((repo) => (
                    <div
                      key={repo.id}
                      className="flex items-center justify-between p-3 border-b border-border last:border-b-0 hover:bg-muted/50 transition-colors"
                    >
                      <div className="flex items-center gap-3 text-left min-w-0 flex-1">
                        <FolderSearch className="w-4 h-4 text-muted-foreground flex-shrink-0" />
                        <div className="min-w-0">
                          <p className="font-mono text-sm truncate">{repo.full_name}</p>
                          <p className="text-xs text-muted-foreground truncate">
                            {repo.description || "No description"}
                          </p>
                        </div>
                      </div>
                      <button
                        onClick={() => analyzeRepo(repo)}
                        disabled={analyzingRepo === (repo.full_name || `${repo.owner?.login}/${repo.name}`)}
                        className="flex-shrink-0 px-3 py-1.5 bg-primary/10 border border-primary/20 rounded-md font-mono text-xs text-primary hover:bg-primary/20 transition-colors disabled:opacity-50 ml-2"
                      >
                        {analyzingRepo === (repo.full_name || `${repo.owner?.login}/${repo.name}`) ? (
                          <Loader2 className="w-3 h-3 animate-spin" />
                        ) : (
                          "Analyze"
                        )}
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>

        {/* Stats */}
        <div className="relative z-10 mt-16 flex gap-12">
          {[
            { value: "2×", label: "free audits", highlight: "2" },
            { value: "~30s", label: "avg scan time", highlight: "30" },
            { value: "∞", label: "with your API key", highlight: null },
          ].map((stat) => (
            <div key={stat.label} className="text-left">
              <div className="text-[28px] font-extrabold tracking-tight">
                {stat.highlight ? (
                  <>
                    <span className="text-primary">{stat.value.replace(stat.highlight, "")}</span>
                    <span className="text-primary">{stat.highlight}</span>
                  </>
                ) : (
                  <span className="text-primary">{stat.value}</span>
                )}
              </div>
              <div className="font-mono text-[11px] text-muted-foreground mt-0.5">{stat.label}</div>
            </div>
          ))}
        </div>
      </section>

      {/* Results Section */}
      {(hasAudited || analyzingRepo) && (
        <section id="results" className="py-10 px-6 md:px-10 border-t border-border">
          <div className="max-w-[1100px] mx-auto">
            {/* Analyzing Animation with Progress */}
            {analyzingRepo && jobStatus && (
              <div className="mb-6 p-6 bg-surface border border-border rounded-xl">
                <div className="flex items-center justify-center gap-4 mb-4">
                  <Loader2 className="w-6 h-6 text-primary animate-spin" />
                  <div>
                    <p className="font-mono text-sm">Analyzing {analyzingRepo}...</p>
                    <p className="text-xs text-muted-foreground">
                      {jobStatus.status === "queued" && "Waiting in queue..."}
                      {jobStatus.status === "running" && jobStatus.progress < 20 && "Fetching repository files..."}
                      {jobStatus.status === "running" && jobStatus.progress >= 20 && jobStatus.progress < 50 && "Parsing code structure..."}
                      {jobStatus.status === "running" && jobStatus.progress >= 50 && jobStatus.progress < 70 && "Scanning for vulnerabilities..."}
                      {jobStatus.status === "running" && jobStatus.progress >= 70 && jobStatus.progress < 85 && "Analyzing dependencies..."}
                      {jobStatus.status === "running" && jobStatus.progress >= 85 && "Generating report..."}
                      {jobStatus.status === "completed" && "Complete!"}
                    </p>
                  </div>
                </div>
                <div className="w-full bg-muted rounded-full h-2">
                  <div 
                    className="bg-primary h-2 rounded-full transition-all duration-500" 
                    style={{ width: `${jobStatus.progress}%` }}
                  />
                </div>
                <div className="mt-2 text-center">
                  <p className="font-mono text-xs text-muted-foreground">
                    {jobStatus.progress < 30 && "⏱ Est. 10-20 seconds"}
                    {jobStatus.progress >= 30 && jobStatus.progress < 70 && "⏱ Est. 15-30 seconds"}
                    {jobStatus.progress >= 70 && "⏱ Almost done..."}
                  </p>
                </div>
              </div>
            )}
            
            {/* Repo Info */}
            <div className="mb-4 p-4 bg-surface border border-border rounded-lg">
              <div className="flex items-center gap-3">
                <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
                  <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z" />
                </svg>
                <span className="font-mono text-sm font-semibold">
                  {hasAudited ? (repoInfo?.scan?.repo?.name || repoInfo?.repo?.name || repoInfo?.name || "Unknown") : "Select a repo to audit"}
                </span>
                <span className="text-xs text-muted-foreground">
                  {hasAudited ? `⭐ ${repoInfo?.scan?.repo?.stars || repoInfo?.stars || 0} · ${repoInfo?.scan?.repo?.language || repoInfo?.language || "Unknown"}` : ""}
                </span>
              </div>
            </div>
            
            <CreditsBar used={0} total={50} />
            
            <div className="mt-4 bg-surface border border-border rounded-xl overflow-hidden">
              <div className="p-5 px-6 border-b border-border">
                <div className="flex gap-2 flex-wrap">
                  {(() => {
                    const vulns = data.vulnerabilities || [];
                    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
                    vulns.forEach((v: any) => {
                      if (v.severity in counts) {
                        counts[v.severity as keyof typeof counts]++;
                      }
                    });
                    return (["critical", "high", "medium", "low"] as Severity[]).map((sev) => (
                      <SeverityPill key={sev} severity={sev} count={counts[sev] || 0} />
                    ));
                  })()}
                </div>
              </div>
            </div>
            
            <ScoreRing score={data.score} grade={data.grade} />
            
            <div className="p-4 flex flex-col gap-2.5">
              {data.vulnerabilities && data.vulnerabilities.length > 0 ? (
                data.vulnerabilities.slice(0, 50).map((vuln: any, idx: number) => (
                  <VulnerabilityCard key={vuln.id || idx} vulnerability={vuln} />
                ))
              ) : (
                <div className="p-8 text-center text-muted-foreground font-mono text-sm">
                  ✅ No vulnerabilities found! Your code looks secure.
                </div>
              )}
            </div>
          </div>
        </section>
      )}

      {/* Footer - removed sign out button, now in navbar */}
    </>
  );
};

export default Dashboard;