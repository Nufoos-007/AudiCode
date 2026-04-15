import { useEffect, useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import { User } from "@supabase/supabase-js";
import { signOut, getCurrentUser } from "../lib/supabase";
import { mockAuditResult } from "../data/mockData";
import ScoreRing from "../components/ScoreRing";
import SeverityPill from "../components/SeverityPill";
import VulnerabilityCard from "../components/VulnerabilityCard";
import CreditsBar from "../components/CreditsBar";
import { Severity } from "../types/audit";
import { LogOut, Github, AlertTriangle } from "lucide-react";

interface RepoInfo {
  full_name: string;
  description: string;
  stargazers_count: number;
  language: string;
  html_url: string;
}

const Dashboard = () => {
  const navigate = useNavigate();
  const [user, setUser] = useState<User | null>(null);
  const [repoInfo, setRepoInfo] = useState<RepoInfo | null>(null);
  const [hasAudited, setHasAudited] = useState(false);

  useEffect(() => {
    const checkUser = async () => {
      const currentUser = await getCurrentUser();
      if (!currentUser) {
        navigate("/");
        return;
      }
      setUser(currentUser);
      
      const stored = sessionStorage.getItem("auditRepo");
      setHasAudited(!!stored);
      if (stored) {
        setRepoInfo(JSON.parse(stored));
      }
    };
    checkUser();
  }, [navigate]);

  const handleSignOut = async () => {
    await signOut();
    sessionStorage.removeItem("auditRepo");
    navigate("/");
  };

  const data = mockAuditResult;

  if (!user) {
    return (
      <div className="min-h-screen pt-[80px] pb-20 px-6 md:px-10 flex items-center justify-center">
        <div className="animate-spin w-6 h-6 border-2 border-primary border-t-transparent rounded-full" />
      </div>
    );
  }

  return (
    <div className="min-h-screen pt-[80px] pb-20 px-6 md:px-10">
      <div className="max-w-[1100px] mx-auto">
        
        {/* Simple Header - User + Sign Out */}
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-3">
            {user.user_metadata?.avatar_url ? (
              <img src={user.user_metadata.avatar_url} alt="" className="w-8 h-8 rounded-full" />
            ) : (
              <div className="w-8 h-8 bg-primary/20 rounded-full flex items-center justify-center">
                <Github className="w-4 h-4 text-primary" />
              </div>
            )}
            <span className="font-mono text-sm text-muted-foreground">{user.user_metadata?.user_name || user.email}</span>
          </div>
          <button
            onClick={handleSignOut}
            className="font-mono text-xs text-muted-foreground hover:text-foreground transition-colors"
          >
            Sign Out
          </button>
        </div>

        {/* Audit Input - Same as Home */}
        <div className="mb-6">
          <h1 className="text-3xl md:text-4xl font-extrabold tracking-tight mb-2">
            Audit another repo
          </h1>
          <p className="text-sm text-muted-foreground mb-4">
            Enter a GitHub repository to scan for vulnerabilities.
          </p>
          <form onSubmit={(e) => { e.preventDefault(); navigate('/'); }} className="flex w-full max-w-[560px]">
            <input
              type="text"
              placeholder="github.com/username/repo"
              className="flex-1 bg-surface border border-border rounded-l-lg px-4 py-3 font-mono text-sm outline-none focus:border-primary"
            />
            <button
              type="submit"
              className="bg-primary text-primary-foreground px-6 py-3 rounded-r-lg font-semibold text-sm whitespace-nowrap hover:opacity-85"
            >
              Audit Now →
            </button>
          </form>
        </div>

        {/* Results - Only show if audited */}
        {hasAudited && repoInfo && (
          <>
            {/* Repo Info */}
            <div className="mb-4 p-4 bg-surface border border-border rounded-lg">
              <div className="flex items-center gap-3">
                <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
                  <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z" />
                </svg>
                <span className="font-mono text-sm font-semibold">{repoInfo.full_name}</span>
                <span className="text-xs text-muted-foreground">
                  ⭐ {repoInfo.stargazers_count} · {repoInfo.language}
                </span>
              </div>
            </div>

            {/* Credits */}
            <CreditsBar used={data.credits.used} total={data.credits.total} />

            {/* Report */}
            <div className="mt-4 bg-surface border border-border rounded-xl overflow-hidden">
              <div className="p-5 px-6 border-b border-border flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
                <div className="flex gap-2 flex-wrap">
                  {(Object.keys(data.summary) as Severity[]).map((sev) => (
                    <SeverityPill key={sev} severity={sev} count={data.summary[sev]} />
                  ))}
              </div>
            </div>

            <ScoreRing score={data.score} grade={data.grade} />

            <div className="p-4 flex flex-col gap-2.5">
              {data.vulnerabilities.map((vuln) => (
                <VulnerabilityCard key={vuln.id} vulnerability={vuln} />
              ))}
            </div>
          </>
        )}

        {/* Empty State - Just prompt to audit */}
        {!hasAudited && (
          <div className="text-center py-12 border border-border rounded-xl">
            <AlertTriangle className="w-12 h-12 text-muted-foreground mx-auto mb-4 opacity-50" />
            <p className="text-muted-foreground">No repository scanned yet.</p>
            <p className="text-sm text-muted-foreground mt-1">Enter a repo above to get started.</p>
          </div>
        )}
      </div>
    </div>
  );
};

export default Dashboard;