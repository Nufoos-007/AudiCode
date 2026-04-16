import type { VercelRequest, VercelResponse } from "@vercel/node";

interface Vulnerability {
  id: string;
  severity: "critical" | "high" | "medium" | "low";
  title: string;
  description: string;
  file: string;
  line: number;
  code: string;
  fix: string;
  category: string;
}

export default async function handler(request: VercelRequest, response: VercelResponse) {
  if (request.method !== "POST") {
    return response.status(405).json({ error: "Method not allowed" });
  }

  const { repoUrl, token } = request.body;
  if (!repoUrl) {
    return response.status(400).json({ error: "Missing repoUrl" });
  }

  try {
    const match = repoUrl.match(/github\.com[/:]([^/]+)\/([^/.]+)/);
    if (!match) {
      return response.status(400).json({ error: "Invalid GitHub URL" });
    }

    const [_, owner, repo] = match;
    const repoName = `${owner}/${repo}`;

    const headers: Record<string, string> = {
      Accept: "application/vnd.github.v3+json",
    };
    
    if (token) {
      headers.Authorization = `token ${token}`;
    }
    
    // Debug: log if we have a token
    console.log("Token available:", !!token);

    const repoRes = await fetch(`https://api.github.com/repos/${repoName}`, { headers });
    if (!repoRes.ok) {
      if (repoRes.status === 404) return response.status(404).json({ error: "Repository not found" });
      if (repoRes.status === 403) return response.status(403).json({ error: "Rate limited. Add a GitHub token." });
      return response.status(400).json({ error: "Failed to fetch repo" });
    }

    const repoData = await repoRes.json();
    const defaultBranch = repoData.default_branch;

    // Collect all files recursively
    const files: Array<{ path: string; content: string; language: string }> = [];
    const scannedPaths = new Set<string>();
    
    async function fetchDir(dirPath: string) {
      const url = `https://api.github.com/repos/${repoName}/contents/${dirPath}?ref=${defaultBranch}`;
      const res = await fetch(url, { headers });
      if (!res.ok) return;
      
      const items = await res.json();
      if (!Array.isArray(items)) return;
      
      for (const item of items.slice(0, 100)) {
        if (item.type === "file" && !scannedPaths.has(item.path)) {
          scannedPaths.add(item.path);
          
          // Get content
          const fileRes = await fetch(item.download_url, { headers });
          if (fileRes.ok) {
            const content = await fileRes.text();
            const ext = item.name.split(".").pop()?.toLowerCase();
            
            // Skip binary and very large files
            if (content.length < 50000 && !item.name.match(/\.(png|jpg|jpeg|gif|pdf|zip|tar|gz|lock)$/i)) {
              files.push({
                path: item.path,
                content,
                language: getLanguage(item.name),
              });
            }
          }
        } else if (item.type === "dir") {
          // Limit depth
          const depth = item.path.split("/").length;
          if (depth < 5 && files.length < 50) {
            await fetchDir(item.path);
          }
        }
      }
    }

    // Start fetching from root
    await fetchDir("");

    const allVulnerabilities: Vulnerability[] = [];
    
    for (const file of files) {
      const findings = scanFile(file);
      allVulnerabilities.push(...findings);
    }

    // Check dependencies
    const dependencyVulns = await checkDependencies(files, repoName, headers);
    allVulnerabilities.push(...dependencyVulns);

    const score = calculateScore(allVulnerabilities);
    const grade = calculateGrade(score);

    return response.status(200).json({
      repo: {
        name: repoData.full_name,
        description: repoData.description,
        stars: repoData.stargazers_count,
        language: repoData.language,
        url: repoData.html_url,
        defaultBranch: repoData.default_branch,
      },
      scan: {
        filesScanned: files.length,
        vulnerabilities: allVulnerabilities,
        score,
        grade,
        summary: summarizeVulnerabilities(allVulnerabilities),
      },
    });
  } catch (error: any) {
    console.error("Scan error:", error);
    return response.status(500).json({ error: "Scan failed" });
  }
}

function getLanguage(filename: string): string {
  const ext = filename.split(".").pop()?.toLowerCase();
  const langMap: Record<string, string> = {
    js: "JavaScript", jsx: "JavaScript", ts: "TypeScript", tsx: "TypeScript",
    py: "Python", rb: "Ruby", go: "Go", rs: "Rust", java: "Java", kt: "Kotlin",
    swift: "Swift", php: "PHP", cs: "C#", c: "C", cpp: "C++", scala: "Scala",
    vue: "Vue", html: "HTML", css: "CSS", json: "JSON", yaml: "YAML", yml: "YAML",
  };
  return langMap[ext || ""] || "Unknown";
}

const SECRET_PATTERNS = [
  { pattern: /sk-[a-zA-Z0-9]{48}/g, type: "OpenAI API key", severity: "critical" as const },
  { pattern: /xAI-[a-zA-Z0-9]{32,}/g, type: "xAI API key", severity: "critical" as const },
  { pattern: /gh[pousr]_[a-zA-Z0-9]{36,}/g, type: "GitHub Token", severity: "critical" as const },
  { pattern: /AKIA[0-9A-Z]{16}/g, type: "AWS Access Key", severity: "critical" as const },
  { pattern: /-----BEGIN PRIVATE KEY-----/g, type: "Private Key", severity: "critical" as const },
  { pattern: /password\s*=\s*["'][^"']{8,}["']/gi, type: "Hardcoded Password", severity: "high" as const },
  { pattern: /api[_-]?key\s*=\s*["'][^"']{16,}["']/gi, type: "API Key", severity: "high" as const },
  { pattern: /secret[_-]?key\s*=\s*["'][^"']{16,}["']/gi, type: "Secret Key", severity: "high" as const },
  { pattern: /bearer\s+[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g, type: "JWT Token", severity: "high" as const },
  { pattern: /eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*/g, type: "JWT Token", severity: "high" as const },
  { pattern: /stripe[_-]?(sk|pk)[a-zA-Z0-9]{24,}/gi, type: "Stripe Key", severity: "critical" as const },
  { pattern: /twilio[_-]?(api[_-]?key|auth[_-]?token)/gi, type: "Twilio Credential", severity: "high" as const },
];

const VULNERABILITY_RULES: Array<{
  pattern: RegExp;
  severity: "critical" | "high" | "medium" | "low";
  title: string;
  description: string;
  fix: string;
  category: string;
}> = [
  { pattern: /eval\s*\(/g, severity: "critical", title: "Dangerous eval() Usage", description: "eval() can execute arbitrary code.", fix: "Use JSON.parse() or safe parser.", category: "Code Injection" },
  { pattern: /exec\s*\(/g, severity: "critical", title: "Dangerous exec() Usage", description: "exec() executes shell commands.", fix: "Avoid exec().", category: "Code Injection" },
  { pattern: /pickle\.loads\s*\(/g, severity: "critical", title: "Insecure Deserialization", description: "pickle can execute arbitrary code.", fix: "Use json instead.", category: "Insecure Deserialization" },
  { pattern: /yaml\.load\s*\(/g, severity: "high", title: "Insecure YAML Parsing", description: "yaml.load can execute code.", fix: "Use yaml.safe_load().", category: "Code Injection" },
  { pattern: /subprocess\.\w*\(\s*shell\s*=\s*True/g, severity: "critical", title: "Shell Injection", description: "shell=True is dangerous.", fix: "Use shell=False.", category: "Command Injection" },
  { pattern: /os\.system\s*\(/g, severity: "high", title: "os.system() Usage", description: "Can be exploited.", fix: "Use subprocess.run().", category: "Command Injection" },
  { pattern: /\.\s*innerHTML\s*=/g, severity: "high", title: "Potential XSS", description: "Direct innerHTML is risky.", fix: "Use textContent.", category: "XSS" },
  { pattern: /dangerouslySetInnerHTML/g, severity: "high", title: "React XSS Risk", description: "Can lead to XSS.", fix: "Sanitize HTML.", category: "XSS" },
  { pattern: /WHERE\s+\w+\s*=\s*["'][^"']*\%s["']|WHERE\s+\w+\s*=\s*f["']/gi, severity: "critical", title: "SQL Injection", description: "String concat in SQL.", fix: "Use parameterized queries.", category: "SQL Injection" },
  { pattern: /cursor\.execute\s*\(\s*["'][^"']*\%s["']/gi, severity: "critical", title: "SQL Injection", description: "String concat in query.", fix: "Use parameterized queries.", category: "SQL Injection" },
  { pattern: /crypto\.createHash\s*\(\s*["']md5["']/g, severity: "high", title: "Weak Crypto (MD5)", description: "MD5 is broken.", fix: "Use SHA-256.", category: "Insecure Cryptography" },
  { pattern: /crypto\.createHash\s*\(\s*["']sha1["']/g, severity: "high", title: "Weak Crypto (SHA1)", description: "SHA1 is weak.", fix: "Use SHA-256.", category: "Insecure Cryptography" },
  { pattern: /Access-Control-Allow-Origin\s*:\s*["']\*["']/g, severity: "high", title: "CORS Misconfiguration", description: "Allowing all origins.", fix: "Specify exact origins.", category: "Access Control" },
  { pattern: /debug\s*=\s*True/gi, severity: "high", title: "Debug Mode", description: "Debug enabled.", fix: "Set DEBUG=False.", category: "Configuration" },
];

function scanFile(file: { path: string; content: string; language: string }): Vulnerability[] {
  const findings: Vulnerability[] = [];
  const lines = file.content.split("\n");
  
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNum = i + 1;
    
    for (const rule of VULNERABILITY_RULES) {
      if (rule.pattern.test(line)) {
        findings.push({
          id: `${file.path}:${lineNum}`,
          severity: rule.severity,
          title: rule.title,
          description: rule.description,
          file: file.path,
          line: lineNum,
          code: line.trim().substring(0, 80),
          fix: rule.fix,
          category: rule.category,
        });
      }
    }
    
    for (const secret of SECRET_PATTERNS) {
      if (secret.pattern.test(line)) {
        findings.push({
          id: `secret-${file.path}:${lineNum}`,
          severity: secret.severity,
          title: `${secret.type} Detected`,
          description: `Found ${secret.type.toLowerCase()}.`,
          file: file.path,
          line: lineNum,
          code: line.trim().substring(0, 80),
          fix: "Use environment variables.",
          category: "Secrets",
        });
      }
    }
  }
  
  return findings;
}

async function checkDependencies(
  files: Array<{ path: string; content: string; language: string }>,
  repoName: string,
  headers: Record<string, string>
): Promise<Vulnerability[]> {
  const vulns: Vulnerability[] = [];
  
  const pkgFile = files.find(f => f.path === "requirements.txt" || f.path === "package.json");
  if (!pkgFile) return vulns;
  
  const pkgs = extractPackages(pkgFile.content);
  
  for (const pkg of pkgs.slice(0, 5)) {
    try {
      const advisoriesRes = await fetch(
        `https://api.github.com/advisories?ecosystem=pip&package=${pkg.name}`,
        { headers }
      );
      
      if (advisoriesRes.ok) {
        const advisories = await advisoriesRes.json();
        if (Array.isArray(advisories) && advisories.length > 0) {
          for (const adv of advisories.slice(0, 2)) {
            vulns.push({
              id: `dep-${pkg.name}`,
              severity: "high",
              title: `Vulnerable: ${pkg.name}`,
              description: `${adv.summary || "Known CVE"} (GHSA: ${adv.ghsa_id})`,
              file: pkgFile.path,
              line: 1,
              code: `${pkg.name}@${pkg.version}`,
              fix: "Update to latest version.",
              category: "Vulnerable Dependency",
            });
          }
        }
      }
    } catch (e) {}
  }
  
  return vulns;
}

function extractPackages(content: string): Array<{ name: string; version: string }> {
  const packages: Array<{ name: string; version: string }> = [];
  
  const pipMatch = content.match(/^([a-zA-Z0-9_-]+)(?:[=<>!~])([^\s#]+)/gm);
  if (pipMatch) {
    for (const m of pipMatch.slice(0, 15)) {
      const parts = m.split(/[=<>!~]/);
      if (parts[0] && parts[1]) {
        packages.push({ name: parts[0], version: parts[1] });
      }
    }
  }
  
  return packages;
}

function summarizeVulnerabilities(vulns: Vulnerability[]): Record<string, number> {
  const summary = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const v of vulns) {
    summary[v.severity]++;
  }
  return summary;
}

function calculateScore(vulnerabilities: Vulnerability[]): number {
  const weights = { critical: 50, high: 20, medium: 5, low: 1 };
  let deductions = 0;
  
  const uniqueByFile = new Map<string, number>();
  for (const v of vulnerabilities) {
    if (!uniqueByFile.has(v.file)) {
      uniqueByFile.set(v.file, 1);
      deductions += weights[v.severity];
    }
  }
  
  deductions = Math.min(deductions, 70);
  return Math.max(0, 100 - deductions);
}

function calculateGrade(score: number): string {
  if (score >= 90) return "A";
  if (score >= 75) return "B";
  if (score >= 60) return "C";
  if (score >= 40) return "D";
  return "F";
}