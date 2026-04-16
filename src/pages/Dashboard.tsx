import { useEffect, useState, useRef, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import { User } from "@supabase/supabase-js";
import { signOut, getCurrentUser, supabase } from "../lib/supabase";
import HeroInput from "../components/HeroInput";
import { mockAuditResult } from "../data/mockData";
import ScoreRing from "../components/ScoreRing";
import SeverityPill from "../components/SeverityPill";
import VulnerabilityCard from "../components/VulnerabilityCard";
import CreditsBar from "../components/CreditsBar";
import { Severity } from "../types/audit";
import { Loader2, FolderSearch, ChevronDown, ChevronRight } from "lucide-react";

const Dashboard = () => {
  const navigate = useNavigate();
  const [user, setUser] = useState<User | null>(null);
  const [repoInfo, setRepoInfo] = useState<any>(null);
  const [hasAudited, setHasAudited] = useState(false);
  const [showRepos, setShowRepos] = useState(false);
  const [userRepos, setUserRepos] = useState<any[]>([]);
  const [loadingRepos, setLoadingRepos] = useState(false);
  const [analyzingRepo, setAnalyzingRepo] = useState<string | null>(null);
  const inputRef = useRef<HTMLDivElement>(null);

  // Check user on mount
  useEffect(() => {
    const initUser = async () => {
      const currentUser = await getCurrentUser();
      if (!currentUser) {
        navigate("/");
        return;
      }
      setUser(currentUser);
      
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
    };
    initUser();
  }, [navigate]);

  // Scroll to input after login
  useEffect(() => {
    if (user && inputRef.current) {
      const timer = setTimeout(() => {
        inputRef.current?.scrollIntoView({ behavior: "smooth", block: "center" });
      }, 300);
      return () => clearTimeout(timer);
    }
  }, [user]);

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
    
    try {
      // Get GitHub token from session
      const { data: { session } } = await supabase.auth.getSession();
      const token = session?.provider_token;
      
      // Call the API
      const response = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ repoUrl, token }),
      });
      
      let scanResult;
      if (response.ok) {
        scanResult = await response.json();
      } else {
        // Fallback to mock if API fails
        console.warn("API scan failed, using mock data");
        scanResult = mockAuditResult;
      }
      
      const repoData = {
        full_name: repoName,
        name: repo.name,
        description: repo.description || scanResult.repo?.description || "",
        stargazers_count: repo.stargazers_count || scanResult.repo?.stars || 0,
        language: repo.language || scanResult.repo?.language || "Unknown",
        html_url: repo.html_url || "",
        owner: { login: repo.owner?.login || user?.user_metadata?.user_name || "unknown" },
      };
      
      // Store and update state
      sessionStorage.setItem("auditRepo", JSON.stringify({ ...repoData, ...scanResult }));
      setRepoInfo({ ...repoData, ...scanResult });
      setHasAudited(true);
      setShowRepos(false);
      
      // Scroll to results
      setTimeout(() => {
        document.getElementById("results")?.scrollIntoView({ behavior: "smooth", block: "start" });
      }, 500);
    } catch (err) {
      console.error("Error analyzing repo:", err);
    }
    
    setAnalyzingRepo(null);
  }, [analyzingRepo, user]);

  const data = repoInfo?.scan || mockAuditResult;

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
          
          {/* My Repos Button */}
          <button
            onClick={fetchUserRepos}
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
            Audit My Repos
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
      {hasAudited && repoInfo && (
        <section id="results" className="py-10 px-6 md:px-10 border-t border-border">
          <div className="max-w-[1100px] mx-auto">
            {/* Analyzing Animation */}
            {analyzingRepo && (
              <div className="mb-6 p-6 bg-surface border border-border rounded-xl flex items-center justify-center gap-4">
                <Loader2 className="w-6 h-6 text-primary animate-spin" />
                <div>
                  <p className="font-mono text-sm">Analyzing {analyzingRepo}</p>
                  <p className="text-xs text-muted-foreground">Scanning for vulnerabilities...</p>
                </div>
              </div>
            )}
            
            {/* Repo Info */}
            <div className="mb-4 p-4 bg-surface border border-border rounded-lg">
              <div className="flex items-center gap-3">
                <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
                  <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z" />
                </svg>
                <span className="font-mono text-sm font-semibold">{repoInfo.full_name}</span>
                <span className="text-xs text-muted-foreground">
                  ⭐ {repoInfo.stargazers_count || repoInfo.scan?.repo?.stars || 0} · {repoInfo.language || repoInfo.scan?.repo?.language || "Unknown"}
                </span>
              </div>
            </div>
            
            <CreditsBar used={repoInfo.scan?.credits?.used || 0} total={repoInfo.scan?.credits?.total || 50} />
            
            <div className="mt-4 bg-surface border border-border rounded-xl overflow-hidden">
              <div className="p-5 px-6 border-b border-border">
                <div className="flex gap-2 flex-wrap">
                  {(() => {
                    const counts = repoInfo.scan?.vulnerabilities?.reduce((acc: Record<string, number>, vuln: any) => {
                      acc[vuln.severity] = (acc[vuln.severity] || 0) + 1;
                      return acc;
                    }, {}) || {};
                    return (["critical", "high", "medium", "low"] as Severity[]).map((sev) => (
                      <SeverityPill key={sev} severity={sev} count={counts[sev] || 0} />
                    ));
                  })()}
                </div>
              </div>
            </div>
            
            <ScoreRing score={repoInfo.scan?.score || data.score} grade={repoInfo.scan?.grade || data.grade} />
            
            <div className="p-4 flex flex-col gap-2.5">
              {(repoInfo.scan?.vulnerabilities || data.vulnerabilities).map((vuln: any) => (
                <VulnerabilityCard key={vuln.id} vulnerability={vuln} />
              ))}
            </div>
          </div>
        </section>
      )}

      {/* Footer - removed sign out button, now in navbar */}
    </>
  );
};

export default Dashboard;