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

    const repoRes = await fetch(`https://api.github.com/repos/${repoName}`, { headers });
    if (!repoRes.ok) {
      if (repoRes.status === 404) return response.status(404).json({ error: "Repository not found" });
      if (repoRes.status === 403) return response.status(403).json({ error: "Rate limited. Add a GitHub token." });
      return response.status(400).json({ error: "Failed to fetch repo" });
    }

    const repoData = await repoRes.json();
    const defaultBranch = repoData.default_branch;

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
          
          const fileRes = await fetch(item.download_url, { headers });
          if (fileRes.ok) {
            const content = await fileRes.text();
            
            if (content.length < 50000 && !item.name.match(/\.(png|jpg|jpeg|gif|pdf|zip|tar|gz|lock|svg)$/i)) {
              files.push({
                path: item.path,
                content,
                language: getLanguage(item.name),
              });
            }
          }
        } else if (item.type === "dir") {
          const depth = item.path.split("/").length;
          if (depth < 5 && files.length < 50) {
            await fetchDir(item.path);
          }
        }
      }
    }

    await fetchDir("");

    const allVulnerabilities: Vulnerability[] = [];
    
    for (const file of files) {
      const findings = scanFile(file);
      allVulnerabilities.push(...findings);
    }

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

// More accurate rules with context checking
const RULES: Array<{
  pattern: RegExp;
  severity: "critical" | "high" | "medium" | "low";
  title: string;
  description: string;
  fix: string;
  exclude?: RegExp;
  requireContext?: string[];
}> = [
  // SQL Injection - only when in execute/query context
  { pattern: /execute\s*\(\s*["'][^"']*["']\.format\s*\(/g, severity: "critical", title: "SQL Injection via .format()", description: "String formatting in SQL query is dangerous.", fix: "Use parameterized queries with placeholders.", exclude: /#.*no.*sql/i },
  { pattern: /execute\s*\(\s*f["'][^"']*SELECT/i, severity: "critical", title: "SQL Injection via f-string", description: "f-string in SQL query allows injection.", fix: "Use parameterized queries.", exclude: /#.*no.*sql/i },
  
  // Deserialization - only for pickle
  { pattern: /pickle\.(loads|load)\s*\(/g, severity: "critical", title: "Insecure Deserialization (pickle)", description: "pickle can deserialize malicious code.", fix: "Use json or MessagePack instead.", exclude: /#.*safe|pickle\.safe/i },
  
  // YAML - only unsafe load
  { pattern: /yaml\.load\s*\(\s*(?!.*safe)/g, severity: "high", title: "Insecure YAML Parsing", description: "yaml.load can execute arbitrary code.", fix: "Use yaml.safe_load() instead.", exclude: /safe_load|safe_load_all/i },
  
  // Shell injection - only when shell=True
  { pattern: /subprocess\.\w+\(\s*shell\s*=\s*True/g, severity: "critical", title: "Shell Injection", description: "shell=True allows command injection.", fix: "Use shell=False and pass argument list.", exclude: /shell\s*=\s*False/i },
  
  // Command injection - os.system
  { pattern: /os\.system\s*\(/g, severity: "high", title: "os.system() Usage", description: "os.system() is vulnerable to command injection.", fix: "Use subprocess.run() with argument list.", exclude: /shell\s*=\s*False/i },
  
  // Hardcoded secrets - only real patterns (longer matches = more likely real)
  { pattern: /sk-[a-zA-Z0-9]{48}/g, severity: "critical", title: "OpenAI API Key", description: "OpenAI key found in code.", fix: "Use environment variables.", exclude: /REPLACE|EXAMPLE|xxx/i },
  { pattern: /xAI-[a-zA-Z0-9]{32,}/g, severity: "critical", title: "xAI API Key", description: "xAI key found in code.", fix: "Use environment variables.", exclude: /REPLACE|EXAMPLE/i },
  { pattern: /AKIA[0-9A-Z]{16}/g, severity: "critical", title: "AWS Access Key", description: "AWS access key found.", fix: "Use AWS Secrets Manager.", exclude: /REPLACE|EXAMPLE/i },
  { pattern: /gh[pousr]_[a-zA-Z0-9]{36,}/g, severity: "critical", title: "GitHub Token", description: "GitHub token found.", fix: "Revoke and use environment variables.", exclude: /REPLACE|EXAMPLE/i },
  { pattern: /eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]{20,}/g, severity: "high", title: "JWT Token", description: "JWT token found.", fix: "Use proper auth flow.", exclude: /REPLACE|EXAMPLE/i },
  { pattern: /stripe[_-]?(sk|pk)[a-zA-Z0-9]{24,}/g, severity: "critical", title: "Stripe Key", description: "Stripe key found.", fix: "Use Stripe dashboard.", exclude: /REPLACE|EXAMPLE/i },
  
  // Hardcoded passwords - minimal length to reduce false positives
  { pattern: /password\s*=\s*["'][a-zA-Z0-9!@#$%^&*()]{20,}["']/gi, severity: "high", title: "Hardcoded Password", description: "Password found in code.", fix: "Use environment variables or secrets manager.", exclude: /REPLACE|EXAMPLE|xxx|default|test/i },
  { pattern: /passwd\s*=\s*["'][a-zA-Z0-9!@#$%^&*()]{20,}["']/gi, severity: "high", title: "Hardcoded Password", description: "Password found in code.", fix: "Use environment variables.", exclude: /REPLACE|EXAMPLE|xxx|default|test/i },
  
  // Weak crypto
  { pattern: /crypto\.createHash\s*\(\s*["']md5["']/g, severity: "high", title: "Weak Crypto (MD5)", description: "MD5 is cryptographically broken.", fix: "Use SHA-256 or stronger.", exclude: /#.*md5|safe/i },
  { pattern: /crypto\.createHash\s*\(\s*["']sha1["']/g, severity: "high", title: "Weak Crypto (SHA1)", description: "SHA1 is cryptographically weak.", fix: "Use SHA-256 or stronger.", exclude: /#.*sha1|safe/i },
  { pattern: /hashlib\.md5\s*\(/g, severity: "high", title: "Weak Crypto (MD5)", description: "MD5 is cryptographically broken.", fix: "Use hashlib.sha256().", exclude: /#.*safe/i },
  { pattern: /hashlib\.sha1\s*\(/g, severity: "high", title: "Weak Crypto (SHA1)", description: "SHA1 is cryptographically weak.", fix: "Use hashlib.sha256().", exclude: /#.*safe/i },
  
  // CORS wildcards
  { pattern: /Access-Control-Allow-Origin\s*:\s*["']\*["']/g, severity: "high", title: "CORS Misconfiguration", description: "Allowing all origins is a security risk.", fix: "Specify exact origins.", exclude: /localhost|dev/i },
  
  // XSS in React - only dangerouslySetInnerHTML
  { pattern: /dangerouslySetInnerHTML\s*=\s*\{\s*__html\s*:/g, severity: "high", title: "React XSS Risk", description: "dangerouslySetInnerHTML can lead to XSS.", fix: "Sanitize HTML or use textContent instead.", exclude: /sanitize|dangerously/i },
  
  // Debug mode in production
  { pattern: /DEBUG\s*=\s*True/gi, severity: "high", title: "Debug Mode Enabled", description: "Debug mode should be disabled in production.", fix: "Set DEBUG=False in production.", exclude: /False|production/i },
  
  // Insecure random for crypto
  { pattern: /Math\.random\s*\(\s*\)/g, severity: "medium", title: "Insecure Random", description: "Math.random is not cryptographically secure.", fix: "Use crypto.getRandomValues() or crypto.randomUUID().", exclude: /test|mock/i },
];

function scanFile(file: { path: string; content: string; language: string }): Vulnerability[] {
  const findings: Vulnerability[] = [];
  
  // Skip files that would cause false positives
  const skipPaths = ["node_modules", "__pycache__", ".git", "dist/", "build/", "test/", "mock/", "fixture/", "example/", ".semgrep"];
  // Only skip specific files, not our scanner (we need to scan it!)
  // But skip chart.tsx which has legitimate dangerouslySetInnerHTML for CSS theming
  if (skipPaths.some(p => file.path.includes(p))) {
    return findings;
  }
  if (file.path.includes("components/ui/chart.tsx")) {
    return findings;
  }
  
  // Skip test files
  if (file.path.match(/\.(test|spec|mock)\.(ts|js|tsx|py)$/i)) {
    return findings;
  }
  
  // Skip test files
  if (file.path.match(/\.(test|spec|mock)\.(ts|js|tsx|py)$/i)) {
    return findings;
  }
  
  const lines = file.content.split("\n");
  const content = file.content;
  
  for (const rule of RULES) {
    let match;
    const regex = new RegExp(rule.pattern.source, rule.pattern.flags);
    
    while ((match = regex.exec(content)) !== null) {
      const lineNum = content.substring(0, match.index).split("\n").length;
      const line = lines[lineNum - 1] || "";
      
      // Check exclusions
      if (rule.exclude && rule.exclude.test(line)) {
        continue;
      }
      
      // Check if in test/mock code
      if (line.match(/\/\/.*test|\/\*.*test|describe\(|it\(|test\(|pytest\(/i)) {
        continue;
      }
      
      findings.push({
        id: `${file.path}:${lineNum}`,
        severity: rule.severity,
        title: rule.title,
        description: `${rule.description} Found at line ${lineNum}.`,
        file: file.path,
        line: lineNum,
        code: line.trim().substring(0, 80),
        fix: rule.fix,
        category: rule.title.split(" ")[0],
      });
      
      // Only one finding per rule per file
      break;
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
              title: `Vulnerable Dependency: ${pkg.name}`,
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