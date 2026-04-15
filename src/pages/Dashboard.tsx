import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { getCsrfToken } from "@/lib/utils";
import { fetchRepoContents } from "../lib/github";
import { mockAuditResult } from "../data/mockData";
import ScoreRing from "../components/ScoreRing";
import SeverityPill from "../components/SeverityPill";
import VulnerabilityCard from "../components/VulnerabilityCard";
import CreditsBar from "../components/CreditsBar";
import { Severity } from "../types/audit";

interface RepoInfo {
  full_name: string;
  description: string;
  stargazers_count: number;
  language: string;
  html_url: string;
}

const Dashboard = () => {
  const navigate = useNavigate();
  const [repoInfo, setRepoInfo] = useState<RepoInfo | null>(null);
  const [files, setFiles] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const stored = sessionStorage.getItem("auditRepo");
    if (stored) {
      try {
        setRepoInfo(JSON.parse(stored));
        // Also fetch file tree
        const repo = JSON.parse(stored);
        fetchRepoContents({ owner: repo.owner.login, name: repo.name, fullName: repo.full_name })
          .then(setFiles)
          .catch(() => setFiles([]));
      } catch {
        navigate("/");
      }
    } else {
      navigate("/");
    }
  }, [navigate]);

  // Use mock data if no real data
  const data = mockAuditResult;

  return (
    <div className="min-h-screen pt-[80px] pb-20 px-6 md:px-10">
      <div className="max-w-[1100px] mx-auto">
        {/* Repo Info */}
        {repoInfo && (
          <div className="mb-4 p-4 bg-surface border border-border rounded-lg">
            <div className="flex items-center gap-3">
              <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
                <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z" />
              </svg>
              <span className="font-mono text-sm font-semibold">{repoInfo.full_name}</span>
            </div>
            {repoInfo.description && (
              <p className="text-sm text-muted-foreground mt-2">{repoInfo.description}</p>
            )}
            <div className="flex items-center gap-4 mt-2 text-xs text-muted-foreground">
              <span>⭐ {repoInfo.stargazers_count} stars</span>
              {repoInfo.language && <span>● {repoInfo.language}</span>}
            </div>
          </div>
        )}

        {/* Credits */}
        <CreditsBar used={data.credits.used} total={data.credits.total} />

        {/* Report */}
        <div className="mt-4 bg-surface border border-border rounded-xl overflow-hidden">
          {/* Header */}
          <div className="p-5 px-6 border-b border-border flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
            <div className="flex items-center gap-3">
              <div className="flex items-center gap-1.5 px-2.5 py-1 bg-surface-2 border border-border rounded-md font-mono text-[11px] text-muted-foreground">
                <svg width="12" height="12" viewBox="0 0 16 16" fill="currentColor">
                  <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z" />
                </svg>
                {data.repo}
              </div>
              <span className="font-mono text-[11px] text-muted-foreground">
                Scanned {data.filesScanned} files · {data.scanTime}s
              </span>
            </div>
            <div className="flex gap-2 flex-wrap">
              {(Object.keys(data.summary) as Severity[]).map((sev) => (
                <SeverityPill key={sev} severity={sev} count={data.summary[sev]} />
              ))}
            </div>
          </div>

          {/* Score */}
          <ScoreRing score={data.score} grade={data.grade} />

          {/* Vulnerabilities */}
          <div className="p-4 flex flex-col gap-2.5">
            {data.vulnerabilities.map((vuln) => (
              <VulnerabilityCard key={vuln.id} vulnerability={vuln} />
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;