import type { VercelRequest, VercelResponse } from "@vercel/node";
import { randomUUID } from "crypto";
import { createClient } from "@supabase/supabase-js";

interface JobStatus {
  id: string;
  repoUrl: string;
  status: "queued" | "running" | "completed" | "failed";
  score?: number;
  grade?: string;
  confidence?: number;
  filesScanned?: number;
  error?: string;
  createdAt: string;
  completedAt?: string;
}

const supabaseUrl = process.env.VITE_SUPABASE_URL || process.env.SUPABASE_URL;
const supabaseKey = process.env.VITE_SUPABASE_ANON_KEY || process.env.SUPABASE_SERVICE_KEY;

const supabase = createClient(supabaseUrl || "", supabaseKey || "");

export default async function handler(request: VercelRequest, response: VercelResponse) {
  const { jobId, repoUrl, userId, token } = request.body;

  try {
    // GET /api/jobs?jobId=XXX - Get job status
    if (request.method === "GET" && jobId) {
      const { data: job, error } = await supabase
        .from("audit_jobs")
        .select("*")
        .eq("id", jobId)
        .single();

      if (error || !job) {
        return response.status(404).json({ error: "Job not found" });
      }

      // Get results if completed
      if (job.status === "completed") {
        const { data: results } = await supabase
          .from("audit_results")
          .select("*")
          .eq("job_id", jobId)
          .order("severity", { ascending: true })
          .limit(100);

        return response.status(200).json({
          ...job,
          vulnerabilities: results || [],
        });
      }

      return response.status(200).json(job);
    }

    // POST /api/jobs - Create new scan job
    if (request.method === "POST") {
      if (!repoUrl) {
        return response.status(400).json({ error: "Missing repoUrl" });
      }

      // Validate user has credits (skip for now - can add later)
      // Check rate limiting
      if (userId) {
        const { data: recentJobs } = await supabase
          .from("audit_jobs")
          .select("id")
          .eq("user_id", userId)
          .gte("created_at", new Date(Date.now() - 60000).toISOString());

        if (recentJobs && recentJobs.length >= 3) {
          return response.status(429).json({ 
            error: "Rate limit exceeded. Please wait before starting another scan." 
          });
        }
      }

      // Create job in Supabase
      const jobId = randomUUID();
      const { data: job, error: jobError } = await supabase
        .from("audit_jobs")
        .insert({
          id: jobId,
          user_id: userId || null,
          repo_url: repoUrl,
          status: "queued",
          progress: 0,
        })
        .select()
        .single();

      if (jobError) {
        console.error("Job creation error:", jobError);
        return response.status(500).json({ error: "Failed to create job" });
      }

      // Start async scan in background
      processScanAsync(jobId, repoUrl, token, userId).catch(console.error);

      return response.status(202).json({
        jobId: job.id,
        status: "queued",
        message: "Scan started. Use GET /api/jobs?jobId=<id> to check status.",
      });
    }

    return response.status(405).json({ error: "Method not allowed" });
  } catch (error: any) {
    console.error("Job error:", error);
    return response.status(500).json({ error: error.message || "Job failed" });
  }
}

async function processScanAsync(jobId: string, repoUrl: string, token?: string, userId?: string) {
  try {
    // Update status to running
    await supabase
      .from("audit_jobs")
      .update({ status: "running", progress: 10 })
      .eq("id", jobId);

    // Parse repo URL
    const match = repoUrl.match(/github\.com[/:]([^/]+)\/([^/.]+)/);
    if (!match) {
      await supabase
        .from("audit_jobs")
        .update({ status: "failed", error: "Invalid GitHub URL", progress: 0 })
        .eq("id", jobId);
      return;
    }

    const [_, owner, repo] = match;
    const repoName = `${owner}/${repo}`;

    // Fetch repo
    const headers: Record<string, string> = {
      Accept: "application/vnd.github.v3+json",
    };
    if (token) {
      headers.Authorization = `token ${token}`;
    }

    const repoRes = await fetch(`https://api.github.com/repos/${repoName}`, { headers });
    if (!repoRes.ok) {
      await supabase
        .from("audit_jobs")
        .update({ status: "failed", error: "Repository not found", progress: 0 })
        .eq("id", jobId);
      return;
    }

    await supabase
      .from("audit_jobs")
      .update({ progress: 30 })
      .eq("id", jobId);

    const repoData = await repoRes.json();
    const files = await fetchAllFiles(repoName, repoData.default_branch, headers);

    await supabase
      .from("audit_jobs")
      .update({ progress: 50 })
      .eq("id", jobId);

    // Scan files with AST analyzer
    const vulnerabilities: any[] = [];
    for (let i = 0; i < files.length; i++) {
      const file = files[i];
      const { analyzeFile } = await import("./scanner/analyzer");
      const result = analyzeFile(file.content, file.path);
      vulnerabilities.push(...result.findings);
    }

    await supabase
      .from("audit_jobs")
      .update({ progress: 70 })
      .eq("id", jobId);

    // Check dependencies
    const depVulns = await checkDependencies(files, repoName, headers);
    vulnerabilities.push(...depVulns);

    // Calculate confidence
    const confidence = calculateConfidence(vulnerabilities, files.length);

    // Calculate score and grade
    const score = calculateScore(vulnerabilities);
    const grade = calculateGrade(score);

    await supabase
      .from("audit_jobs")
      .update({ progress: 85 })
      .eq("id", jobId);

    // Store results in Supabase
    if (vulnerabilities.length > 0) {
      const resultsToInsert = vulnerabilities.slice(0, 100).map((v: any) => ({
        job_id: jobId,
        severity: v.severity,
        title: v.title,
        description: v.description,
        file: v.file,
        line: v.line,
        code: v.code,
        fix: v.fix,
        category: v.category,
        cwe: v.cwe,
        owasp: v.owasp,
        confidence: v.confidence,
      }));

      await supabase.from("audit_results").insert(resultsToInsert);
    }

    // Update job with final results
    await supabase
      .from("audit_jobs")
      .update({
        status: "completed",
        progress: 100,
        score,
        grade,
        confidence,
        files_scanned: files.length,
        completed_at: new Date().toISOString(),
      })
      .eq("id", jobId);

  } catch (error: any) {
    await supabase
      .from("audit_jobs")
      .update({ 
        status: "failed", 
        error: error.message,
        progress: 0 
      })
      .eq("id", jobId);
  }
}

async function fetchAllFiles(repoName: string, branch: string, headers: Record<string, string>) {
  const files: Array<{ path: string; content: string; language: string }> = [];
  const scanned = new Set<string>();

  async function fetchDir(path: string) {
    const url = `https://api.github.com/repos/${repoName}/contents/${path}?ref=${branch}`;
    const res = await fetch(url, { headers });
    if (!res.ok) return;

    const items = await res.json();
    if (!Array.isArray(items)) return;

    for (const item of items.slice(0, 60)) {
      if (item.type === "file" && !scanned.has(item.path)) {
        scanned.add(item.path);

        if (!item.name.match(/\.(png|jpg|jpeg|gif|pdf|zip|tar|gz|lock|svg|ico)$/i)) {
          const fileRes = await fetch(item.download_url, { headers });
          if (fileRes.ok && item.size < 40000) {
            files.push({
              path: item.path,
              content: await fileRes.text(),
              language: getLanguage(item.name),
            });
          }
        }
      } else if (item.type === "dir" && item.path.split("/").length < 4 && files.length < 40) {
        await fetchDir(item.path);
      }
    }
  }

  await fetchDir("");
  return files;
}

function getLanguage(filename: string): string {
  const ext = filename.split(".").pop()?.toLowerCase();
  const map: Record<string, string> = {
    js: "JavaScript", jsx: "JavaScript", ts: "TypeScript", tsx: "TypeScript",
    py: "Python", rb: "Ruby", go: "Go", rs: "Rust", java: "Java", kt: "Kotlin",
  };
  return map[ext || ""] || "Unknown";
}

// OWASP Scanner Rules
const OWASP_RULES: any[] = [
  { pattern: /sk-[a-zA-Z0-9]{48}/g, severity: "critical", title: "OpenAI Key", category: "Secrets", cwe: "CWE-798", owasp: "A02" },
  { pattern: /gh[pousr]_[a-zA-Z0-9]{36,}/g, severity: "critical", title: "GitHub Token", category: "Secrets", cwe: "CWE-798", owasp: "A02" },
  { pattern: /AKIA[0-9A-Z]{16}/g, severity: "critical", title: "AWS Key", category: "Secrets", cwe: "CWE-798", owasp: "A02" },
  { pattern: /eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]{20,}/g, severity: "critical", title: "JWT Token", category: "Secrets", cwe: "CWE-615", owasp: "A02" },
  { pattern: /execute\s*\(\s*["'][^"']*\$\{/g, severity: "critical", title: "SQL Injection", category: "Injection", cwe: "CWE-89", owasp: "A03" },
  { pattern: /\.innerHTML\s*=/g, severity: "high", title: "XSS Risk", category: "XSS", cwe: "CWE-79", owasp: "A01" },
  { pattern: /dangerouslySetInnerHTML\s*=/g, severity: "high", title: "React XSS", category: "XSS", cwe: "CWE-79", owasp: "A01" },
  { pattern: /crypto\.createHash\s*\(\s*["']md5["']\)/g, severity: "high", title: "Weak Crypto", category: "Crypto", cwe: "CWE-327", owasp: "A02" },
  { pattern: /Math\.random\s*\(\s*\)/g, severity: "high", title: "Insecure Random", category: "Crypto", cwe: "CWE-338", owasp: "A02" },
  { pattern: /eval\s*\(/g, severity: "critical", title: "eval() Usage", category: "Injection", cwe: "CWE-95", owasp: "A03" },
  { pattern: /exec\s*\(/g, severity: "critical", title: "exec() Usage", category: "Injection", cwe: "CWE-78", owasp: "A03" },
  { pattern: /Access-Control-Allow-Origin\s*:\s*\*$/gm, severity: "high", title: "Wildcard CORS", category: "Config", cwe: "CWE-346", owasp: "A05" },
  { pattern: /DEBUG\s*=\s*True/gi, severity: "critical", title: "Debug Mode", category: "Config", cwe: "CWE-11", owasp: "A05" },
];

function OWASPScanner(file: { path: string; content: string; language: string }): any[] {
  const findings: any[] = [];

  if (file.path.match(/\.(test|spec|mock)\.(ts|js|tsx|py)$/i)) return findings;
  if (file.path.includes("node_modules/") || file.path.includes("dist/")) return findings;
  if (file.path.includes("api/scan.ts") || file.path.includes("components/ui/chart.tsx")) return findings;

  const content = file.content;
  const lines = content.split("\n");

  for (const rule of OWASP_RULES) {
    let match;
    const regex = new RegExp(rule.pattern.source, rule.pattern.flags);

    while ((match = regex.exec(content)) !== null) {
      const lineNum = content.substring(0, match.index).split("\n").length;
      const line = lines[lineNum - 1] || "";

      if (line.match(/test|spec|mock|describe/i)) continue;

      const confidence = calculateFindingConfidence(line);

      findings.push({
        id: `${file.path}:${lineNum}-${rule.title.replace(/\s/g, "-")}`,
        severity: rule.severity,
        title: rule.title,
        description: `${rule.title} found in ${file.path}`,
        file: file.path,
        line: lineNum,
        code: line.trim().substring(0, 80),
        fix: getFixForRule(rule.title),
        category: rule.category,
        cwe: rule.cwe,
        owasp: rule.owasp,
        confidence,
      });
      break;
    }
  }

  return findings;
}

function calculateFindingConfidence(line: string): number {
  let confidence = 75;
  if (line.match(/\/\/.*test|describe\(|it\(/i)) confidence -= 30;
  if (line.match(/const\s+\w+\s*=|let\s+\w+\s*=/)) confidence += 10;
  if (line.match(/\w+\(/)) confidence += 5;
  return Math.min(95, Math.max(40, confidence));
}

function getFixForRule(title: string): string {
  const fixes: Record<string, string> = {
    "OpenAI Key": "Use environment variables",
    "GitHub Token": "Revoke and use secrets",
    "SQL Injection": "Use parameterized queries",
    "XSS Risk": "Use textContent",
    "React XSS": "Sanitize HTML",
    "Weak Crypto": "Use SHA-256",
    "Insecure Random": "Use crypto.randomUUID()",
    "eval() Usage": "Avoid eval()",
    "exec() Usage": "Use subprocess.run()",
    "Wildcard CORS": "Specify allowed origins",
    "Debug Mode": "Set DEBUG=False",
  };
  return fixes[title] || "Review and fix";
}

async function checkDependencies(files: any[], repoName: string, headers: Record<string, string>): Promise<any[]> {
  const vulns: any[] = [];
  const pkgFile = files.find(f => f.path === "requirements.txt" || f.path === "package.json");
  if (!pkgFile) return vulns;

  const matches = pkgFile.content.match(/^([a-zA-Z0-9_-]+)(?:[=<>!~])([^\s#]+)/gm);
  if (!matches) return vulns;

  for (const m of matches.slice(0, 5)) {
    const [name, version] = m.split(/[=<>!~]/);
    try {
      const res = await fetch(`https://api.github.com/advisories?ecosystem=pip&package=${name}`, { headers });
      if (res.ok) {
        const advisories = await res.json();
        if (Array.isArray(advisories) && advisories.length > 0) {
          for (const adv of advisories.slice(0, 2)) {
            vulns.push({
              id: `dep-${name}`,
              severity: "high",
              title: `Vulnerable: ${name}`,
              description: `${adv.ghsa_id}: ${adv.summary || "CVE"}`,
              file: pkgFile.path,
              line: 1,
              code: `${name}@${version}`,
              fix: `Update ${name}`,
              category: "Supply Chain",
              cwe: "CWE-1594",
              owasp: "A06",
              confidence: 90,
            });
          }
        }
      }
    } catch (e) {}
  }

  return vulns;
}

function calculateConfidence(vulnerabilities: any[], fileCount: number): number {
  if (vulnerabilities.length === 0) return 95;
  const base = 75;
  const fileBonus = Math.min(15, fileCount * 0.3);
  const severityBonus = vulnerabilities.filter(v => v.severity === "critical").length * 5;
  return Math.min(95, Math.max(50, base + fileBonus + severityBonus));
}

function calculateScore(vulnerabilities: any[]): number {
  const weights = { critical: 50, high: 20, medium: 5, low: 1 };
  const uniqueFiles = new Set<string>();
  let deductions = 0;
  for (const v of vulnerabilities) {
    if (!uniqueFiles.has(v.file)) {
      uniqueFiles.add(v.file);
      deductions += weights[v.severity] || 1;
    }
  }
  deductions = Math.min(deductions, 65);
  return Math.max(0, 100 - deductions);
}

function calculateGrade(score: number): string {
  if (score >= 90) return "A";
  if (score >= 75) return "B";
  if (score >= 60) return "C";
  if (score >= 40) return "D";
  return "F";
}