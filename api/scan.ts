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
  cwe: string;
  owasp: string;
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

    const repoRes = await fetch(`https://api.github.com/repos/${repoName}`, { headers });
    if (!repoRes.ok) {
      return response.status(404).json({ error: "Repository not found" });
    }

    const repoData = await repoRes.json();
    const files = await fetchAllFiles(repoName, repoData.default_branch, headers);

    const allVulnerabilities: Vulnerability[] = [];
    
    for (const file of files) {
      const findings = OWASPScanner(file);
      allVulnerabilities.push(...findings);
    }

    const dependencyVulns = await checkDependencies(files, repoName, headers);
    allVulnerabilities.push(...dependencyVulns);

    const score = calculateOWASPScore(allVulnerabilities);
    const grade = calculateGrade(score);
    const summary = OWASPSummary(allVulnerabilities);

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
        summary,
        owaspCategories: summarizeByOWASP(allVulnerabilities),
      },
    });
  } catch (error: any) {
    console.error("Scan error:", error);
    return response.status(500).json({ error: "Scan failed" });
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
    
    for (const item of items.slice(0, 100)) {
      if (item.type === "file" && !scanned.has(item.path)) {
        scanned.add(item.path);
        
        if (!item.name.match(/\.(png|jpg|jpeg|gif|pdf|zip|tar|gz|lock|svg|ico)$/i)) {
          const fileRes = await fetch(item.download_url, { headers });
          if (fileRes.ok && item.size < 50000) {
            files.push({
              path: item.path,
              content: await fileRes.text(),
              language: getLanguage(item.name),
            });
          }
        }
      } else if (item.type === "dir") {
        if (item.path.split("/").length < 5 && files.length < 60) {
          await fetchDir(item.path);
        }
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
    swift: "Swift", php: "PHP", cs: "C#", c: "C", cpp: "C++", vue: "Vue",
  };
  return map[ext || ""] || "Unknown";
}

// Comprehensive OWASP Rules for Vibe-Coded Apps
const OWASP_RULES: Array<{
  pattern: RegExp; severity: Vulnerability["severity"]; title: string;
  description: string; fix: string; category: string; cwe: string; owasp: string;
  exclude?: RegExp;
}> = [
  // A01: Broken Access Control
  { pattern: /router\.(get|post|put|delete)\s*\([^)]*,\s*(?!\w*[Aa]uth|\w*[Pp]ermissions)/g, severity: "critical", title: "Unprotected API Route", description: "API route has no auth middleware", fix: "Add auth middleware to verify user identity", category: "Access Control", cwe: "CWE-284", owasp: "A01" },
  { pattern: /supabase\.from\([^)]*\)\.select\(\)/g, severity: "high", title: "Missing RLS Policy", description: "Supabase query without Row Level Security", fix: "Enable RLS and add policies", category: "Access Control", cwe: "CWE-284", owasp: "A01", exclude: /\.rpc\(/ },
  { pattern: /app\.get\s*\(\s*["'][^"']*\/api\/[^"']*/, severity: "high", title: "Public API Endpoint", description: "API route accessible without authentication", fix: "Add authentication check", category: "Access Control", cwe: "CWE-284", owasp: "A01", exclude: /auth|login|public/i },
  
  // A02: Cryptographic Failures
  { pattern: /Math\.random\s*\(\s*\)/g, severity: "high", title: "Insecure Random for Tokens", description: "Math.random is not cryptographically secure", fix: "Use crypto.randomUUID() or crypto.getRandomValues()", category: "Cryptography", cwe: "CWE-338", owasp: "A02", exclude: /test|mock/i },
  { pattern: /crypto\.createHash\s*\(\s*["']md5["']\)/g, severity: "critical", title: "Weak Hash (MD5)", description: "MD5 is cryptographically broken", fix: "Use SHA-256 or bcrypt", category: "Cryptography", cwe: "CWE-327", owasp: "A02" },
  { pattern: /crypto\.createHash\s*\(\s*["']sha1["']\)/g, severity: "high", title: "Weak Hash (SHA1)", description: "SHA1 is cryptographically weak", fix: "Use SHA-256", category: "Cryptography", cwe: "CWE-327", owasp: "A02" },
  { pattern: /bcrypt\.hashSync\s*\([^,]{1,10}\)/g, severity: "medium", title: "Weak bcrypt iterations", description: "Low bcrypt cost factor", fix: "Use cost factor 12+", category: "Cryptography", cwe: "CWE-327", owasp: "A02" },
  { pattern: /jwt\.sign\([^,]+,\s*[^,]+,\s*\{[^}]*expiresIn[^}]*\}/g, severity: "medium", title: "Short JWT Expiration", description: "JWT expires too quickly", fix: "Set appropriate expiration", category: "Cryptography", cwe: "CWE-613", owasp: "A02" },
  
  // A03: Injection
  { pattern: /execute\s*\(\s*["'][^"']*\${\s*\w+\s*["']/g, severity: "critical", title: "SQL Injection (Template)", description: "String interpolation in SQL query", fix: "Use parameterized queries", category: "Injection", cwe: "CWE-89", owasp: "A03", exclude: /safe|param|prepare/i },
  { pattern: /execute\s*\(\s*f["'][^"']*SELECT.*\{\w+\}/g, severity: "critical", title: "SQL Injection (f-string)", description: "f-string in SQL query allows injection", fix: "Use parameterized queries", category: "Injection", cwe: "CWE-89", owasp: "A03" },
  { pattern: /query\s*\(\s*\{[^}]*\$where[^}]*\}/g, severity: "critical", title: "NoSQL Injection", description: "MongoDB query with unsanitized input", fix: "Validate and sanitize input", category: "Injection", cwe: "CWE-943", owasp: "A03" },
  { pattern: /db\.execute\s*\(\s*["'][^"']*\+[^"']*\)/g, severity: "critical", title: "SQL Injection (concat)", description: "String concatenation in SQL", fix: "Use parameterized queries", category: "Injection", cwe: "CWE-89", owasp: "A03" },
  { pattern: /eval\s*\(/g, severity: "critical", title: "Dangerous eval()", description: "eval() executes arbitrary code", fix: "Avoid eval(), use alternatives", category: "Injection", cwe: "CWE-95", owasp: "A03" },
  { pattern: /exec\s*\(/g, severity: "critical", title: "Dangerous exec()", description: "exec() runs shell commands", fix: "Use safer alternatives", category: "Injection", cwe: "CWE-78", owasp: "A03" },
  
  // A04: Insecure Design
  { pattern: /rateLimit\s*:\s*(false|null)/g, severity: "medium", title: "No Rate Limiting", description: "Endpoint has no rate limiting", fix: "Add rate limiting", category: "Design", cwe: "CWE-770", owasp: "A04" },
  
  // A05: Security Misconfiguration  
  { pattern: /Access-Control-Allow-Origin\s*:\s*\*$/gm, severity: "high", title: "Wildcard CORS", description: "Allowing all origins is insecure", fix: "Specify exact allowed origins", category: "Config", cwe: "CWE-346", owasp: "A05" },
  { pattern: /DEBUG\s*=\s*True/gi, severity: "critical", title: "Debug Mode in Production", description: "Debug mode enabled in production", fix: "Set DEBUG=False", category: "Config", cwe: "CWE-11", owasp: "A05" },
  { pattern: /cors\s*:\s*\{[^}]*origin\s*:\s*\*[^}]*\}/g, severity: "high", title: "CORS Wildcard", description: "CORS allows all origins", fix: "Restrict to specific domains", category: "Config", cwe: "CWE-346", owasp: "A05" },
  { pattern: /express\.json\(\)/g, severity: "low", title: "No Input Validation", description: "Express.json without validation", fix: "Add input validation", category: "Config", cwe: "CWE-20", owasp: "A05" },
  
  // A07: Authentication Failures  
  { pattern: /jwt\.verify\([^,]+,\s*["'][^"']{10,30}["']\)/g, severity: "high", title: "Hardcoded JWT Secret", description: "JWT secret hardcoded in source", fix: "Use environment variables", category: "Auth", cwe: "CWE-798", owasp: "A07" },
  { pattern: /session\s*=\s*[{"'][^"']{20,}["']/g, severity: "high", title: "Hardcoded Session Secret", description: "Session secret in code", fix: "Use environment variables", category: "Auth", cwe: "CWE-798", owasp: "A07" },
  { pattern: /auth0\s*=\s*["'][^"']+["']/g, severity: "high", title: "Hardcoded Auth0 Secret", description: "Auth0 key in source", fix: "Use Auth0 environment variables", category: "Auth", cwe: "CWE-798", owasp: "A07" },
  { pattern: /Bearer\s+[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g, severity: "medium", title: "Exposed JWT Token", description: "JWT in source or logs", fix: "Don't log tokens", category: "Auth", cwe: "CWE-615", owasp: "A07", exclude: /REPLACE|EXAMPLE/i },
  
  // A08: Software Supply Chain
  { pattern: /"dependencies":\s*\{[^}]*"[^"]*"\s*:\s*"[^"]*git[^"]*"/g, severity: "medium", title: "Git Dependency", description: "Dependency from git may be untrusted", fix: "Use official registries", category: "Supply Chain", cwe: "CWE-1594", owasp: "A08" },
  { pattern: /npm\s+install[^|]*\|[^|]*bash/g, severity: "low", title: "Shell in Install Script", description: "Install script runs shell commands", category: "Supply Chain", cwe: "CWE-1594", owasp: "A08" },
  
  // A09: Logging Failures
  { pattern: /console\.log\([^)]*(password|secret|token|key|auth)[^)]*\)/gi, severity: "critical", title: "Sensitive Data in Logs", description: "Credentials logged", fix: "Remove sensitive data from logs", category: "Logging", cwe: "CWE-532", owasp: "A09", exclude: /test|mock/i },
  { pattern: /logger\.[a-z]+\([^)]*(password|secret|token|key)[^)]*\)/gi, severity: "high", title: "Sensitive Data in Logs", description: "Credentials logged", fix: "Redact sensitive data", category: "Logging", cwe: "CWE-532", owasp: "A09", exclude: /test|mock/i },
  { pattern: /error_log\([^)]*(password|secret|token|key)[^)]*\)/gi, severity: "high", title: "Sensitive Data in Error Logs", description: "Credentials in error logs", fix: "Redact sensitive data", category: "Logging", cwe: "CWE-532", owasp: "A09" },
  
  // A10: SSRF
  { pattern: /fetch\s*\(\s*[^,]*\+[^,]*url/gi, severity: "critical", title: "Potential SSRF", description: "URL built from user input", fix: "Validate and whitelist URLs", category: "SSRF", cwe: "CWE-918", owasp: "A10" },
  { pattern: /axios\.get\s*\(\s*[^,]*\+[^,]*url/gi, severity: "critical", title: "Potential SSRF", description: "URL built from user input", fix: "Validate URLs", category: "SSRF", cwe: "CWE-918", owasp: "A10" },
  { pattern: /request\s*\(\s*\{[^}]*url[^}]*\+[^}]*\}/g, severity: "critical", title: "Potential SSRF", description: "URL concatenation with user input", fix: "Validate URLs", category: "SSRF", cwe: "CWE-918", owasp: "A10" },
  
  // Secrets Detection
  { pattern: /sk-[a-zA-Z0-9]{48}/g, severity: "critical", title: "OpenAI Key Exposed", description: "OpenAI API key found in code", fix: "Use environment variables", category: "Secrets", cwe: "CWE-798", owasp: "A02" },
  { pattern: /xAI-[a-zA-Z0-9]{32,}/g, severity: "critical", title: "xAI Key Exposed", description: "xAI API key found", fix: "Use environment variables", category: "Secrets", cwe: "CWE-798", owasp: "A02" },
  { pattern: /AKIA[0-9A-Z]{16}/g, severity: "critical", title: "AWS Key Exposed", description: "AWS access key found", fix: "Use AWS Secrets Manager", category: "Secrets", cwe: "CWE-798", owasp: "A02" },
  { pattern: /gh[pousr]_[a-zA-Z0-9]{36,}/g, severity: "critical", title: "GitHub Token Exposed", description: "GitHub token found", fix: "Revoke and rotate", category: "Secrets", cwe: "CWE-798", owasp: "A02" },
  { pattern: /eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]{20,}/g, severity: "critical", title: "JWT Token Exposed", description: "JWT token found", fix: "Regenerate JWT", category: "Secrets", cwe: "CWE-615", owasp: "A02" },
  { pattern: /sk_live_[a-zA-Z0-9]{24,}/g, severity: "critical", title: "Stripe Live Key", description: "Stripe live key exposed", fix: "Use test key", category: "Secrets", cwe: "CWE-798", owasp: "A02" },
  
  // XSS (A01/A03 related)
  { pattern: /dangerouslySetInnerHTML\s*=\s*\{\s*__html\s*:/g, severity: "high", title: "React XSS Risk", description: "dangerouslySetInnerHTML can cause XSS", fix: "Sanitize HTML", category: "XSS", cwe: "CWE-79", owasp: "A01" },
  { pattern: /\.innerHTML\s*=/g, severity: "high", title: "DOM XSS Risk", description: "Direct innerHTML assignment", fix: "Use textContent", category: "XSS", cwe: "CWE-79", owasp: "A01" },
];

function OWASPScanner(file: { path: string; content: string; language: string }): Vulnerability[] {
  const findings: Vulnerability[] = [];
  
  // Skip test/mock files to reduce false positives
  if (file.path.match(/\.(test|spec|mock)\.(ts|js|tsx|py)$/i)) return findings;
  if (file.path.includes("/node_modules/")) return findings;
  if (file.path.includes("/__pycache__/")) return findings;
  if (file.path.includes("dist/") || file.path.includes("build/")) return findings;
  if (file.path.includes("components/ui/chart.tsx")) return findings;
  
  const content = file.content;
  const lines = content.split("\n");
  
  for (const rule of OWASP_RULES) {
    let match;
    const regex = new RegExp(rule.pattern.source, rule.pattern.flags);
    
    while ((match = regex.exec(content)) !== null) {
      const lineNum = content.substring(0, match.index).split("\n").length;
      const line = lines[lineNum - 1] || "";
      
      // Check exclusions
      if (rule.exclude && rule.exclude.test(line)) continue;
      // Skip test code
      if (line.match(/test|spec|mock|describe|it\(/i)) continue;
      
      findings.push({
        id: `${file.path}:${lineNum}-${rule.title.replace(/\s/g, "-")}`,
        severity: rule.severity,
        title: rule.title,
        description: rule.description,
        file: file.path,
        line: lineNum,
        code: line.trim().substring(0, 80),
        fix: rule.fix,
        category: rule.category,
        cwe: rule.cwe,
        owasp: rule.owasp,
      });
      
      break; // One finding per rule per file
    }
  }
  
  return findings;
}

async function checkDependencies(files: any[], repoName: string, headers: Record<string, string>): Promise<Vulnerability[]> {
  const vulns: Vulnerability[] = [];
  const pkgFile = files.find(f => f.path === "requirements.txt" || f.path === "package.json");
  if (!pkgFile) return vulns;
  
  const pkgs = extractPackages(pkgFile.content);
  
  for (const pkg of pkgs.slice(0, 8)) {
    try {
      const res = await fetch(`https://api.github.com/advisories?ecosystem=pip&package=${pkg.name}`, { headers });
      if (res.ok) {
        const advisories = await res.json();
        if (Array.isArray(advisories) && advisories.length > 0) {
          for (const adv of advisories.slice(0, 2)) {
            vulns.push({
              id: `dep-${pkg.name}`,
              severity: "high",
              title: `Vulnerable Dependency: ${pkg.name}`,
              description: `${adv.ghsa_id}: ${adv.summary || "Known CVE"}`,
              file: pkgFile.path,
              line: 1,
              code: `${pkg.name}@${pkg.version}`,
              fix: `Update ${pkg.name} to latest version`,
              category: "Supply Chain",
              cwe: "CWE-1594",
              owasp: "A08",
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
  const matches = content.match(/^([a-zA-Z0-9_-]+)(?:[=<>!~])([^\s#]+)/gm);
  if (matches) {
    for (const m of matches.slice(0, 15)) {
      const parts = m.split(/[=<>!~]/);
      if (parts[0] && parts[1]) packages.push({ name: parts[0], version: parts[1] });
    }
  }
  return packages;
}

function OWASPSummary(vulns: Vulnerability[]): Record<string, number> {
  const summary = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const v of vulns) summary[v.severity]++;
  return summary;
}

function summarizeByOWASP(vulns: Vulnerability[]): Record<string, number> {
  const byCategory: Record<string, number> = {};
  for (const v of vulns) {
    byCategory[v.owasp] = (byCategory[v.owasp] || 0) + 1;
  }
  return byCategory;
}

function calculateOWASPScore(vulns: Vulnerability[]): number {
  const weights = { critical: 50, high: 20, medium: 5, low: 1 };
  const uniqueFiles = new Set<string>();
  
  for (const v of vulns) {
    if (!uniqueFiles.has(v.file)) {
      uniqueFiles.add(v.file);
    }
  }
  
  let deductions = 0;
  for (const v of vulns) {
    deductions += weights[v.severity];
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