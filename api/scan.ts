import type { VercelRequest, VercelResponse } from "@vercel/node";

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

    const contentsRes = await fetch(
      `https://api.github.com/repos/${repoName}/contents?ref=${repoData.default_branch}`,
      { headers }
    );

    const files: Array<{ path: string; content: string; language: string }> = [];

    if (contentsRes.ok) {
      const contents = await contentsRes.json();
      const fileList = Array.isArray(contents) ? contents.slice(0, 50) : [];
      
      for (const file of fileList) {
        if (file.type === "file") {
          const fileRes = await fetch(file.download_url, { headers });
          if (fileRes.ok) {
            const content = await fileRes.text();
            if (isCodeFile(file.path) || file.size < 50000) {
          const fileRes = await fetch(file.download_url, { headers });
          if (fileRes.ok) {
            const content = await fileRes.text();
            files.push({
              path: file.path,
              content,
              language: getLanguage(file.path),
            });
          }
        }
      }
    }

    const allVulnerabilities: Vulnerability[] = [];
    
    for (const file of files) {
      const findings = scanFile(file);
      allVulnerabilities.push(...findings);
    }

    const dependencyVulns = await checkDependencies(repoName, files, headers);
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

function isCodeFile(path: string): boolean {
  // Allow all relevant files
  const ext = path.split(".").pop()?.toLowerCase();
  const codeExtensions = [
    "js", "jsx", "ts", "tsx", "py", "rb", "go", "rs", "java", "kt",
    "swift", "php", "cs", "c", "cpp", "h", "hpp", "scala", "vue",
    "json", "yaml", "yml", "toml", "ini", "cfg", "conf", "sh", "bash", "zsh",
  ];
  if (codeExtensions.includes(ext || "")) return true;
  
  // Allow important config files
  const importantFiles = [
    "package.json", "requirements.txt", "setup.py", "Pipfile", "pyproject.toml",
    "Dockerfile", "docker-compose.yml", ".dockerignore", ".gitignore",
    "Makefile", "CMakeLists.txt", "webpack.config.js", "vite.config.ts",
    "next.config.js", "tsconfig.json", "babel.config.js", ".env",
  ];
  if (importantFiles.includes(path)) return true;
  
  return path.includes("/src/") || path.includes("/lib/") || path.includes("/core/") || path.includes("/app/");
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
  { pattern: /sk-[a-zA-Z0-9]{48}/g, type: "OpenAI API key", severity: "critical" },
  { pattern: /sk-proj-[a-zA-Z0-9_-]{48,}/g, type: "OpenAI Project key", severity: "critical" },
  { pattern: /xAI-[a-zA-Z0-9]{32,}/g, type: "xAI API key", severity: "critical" },
  { pattern: /AI[a-zA-Z0-9_-]*key\s*=\s*["'][^"']+["']/gi, type: "Generic AI API key", severity: "high" },
  { pattern: /github[_-]?token\s*=\s*["'][^"']{40,}["']/gi, type: "GitHub Token", severity: "critical" },
  { pattern: /gh[pousr]_[a-zA-Z0-9]{36,}/g, type: "GitHub Personal Access Token", severity: "critical" },
  { pattern: /gho_[a-zA-Z0-9]{36}/g, type: "GitHub OAuth Token", severity: "critical" },
  { pattern: /ghs_[a-zA-Z0-9]{36}/g, type: "GitHub Server Token", severity: "critical" },
  { pattern: /ghr_[a-zA-Z0-9]{36}/g, type: "GitHub Refresh Token", severity: "critical" },
  { pattern: /AKIA[0-9A-Z]{16}/g, type: "AWS Access Key", severity: "critical" },
  { pattern: /aws[_-]?secret[_-]?access[_-]?key/gi, type: "AWS Secret Key", severity: "critical" },
  { pattern: /-----BEGIN PRIVATE KEY-----/g, type: "Private Key", severity: "critical" },
  { pattern: /password\s*=\s*["'][^"']{8,}["']/gi, type: "Hardcoded Password", severity: "high" },
  { pattern: /passwd\s*=\s*["'][^"']{8,}["']/gi, type: "Hardcoded Password", severity: "high" },
  { pattern: /api[_-]?key\s*=\s*["'][^"']{16,}["']/gi, type: "API Key", severity: "high" },
  { pattern: /secret[_-]?key\s*=\s*["'][^"']{16,}["']/gi, type: "Secret Key", severity: "high" },
  { pattern: /bearer\s+[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g, type: "JWT Token", severity: "high" },
  { pattern: /eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*/g, type: "JWT Token", severity: "high" },
  { pattern: /slack[_-]?token\s*=.*xox[baprs]/gi, type: "Slack Token", severity: "high" },
  { pattern: /sq0csp-[0-9A-Za-z_-]{43}/g, type: "Square API Key", severity: "high" },
  { pattern: /sq0atp-[0-9A-Za-z_-]{22}/g, type: "Square Access Token", severity: "high" },
  { pattern: /stripe[_-]?(sk|pk)[a-zA-Z0-9]{24,}/gi, type: "Stripe Key", severity: "critical" },
  { pattern: /twilio[_-]?(api[_-]?key|auth[_-]?token)/gi, type: "Twilio Credential", severity: "high" },
  { pattern: /sendgrid[_-]?api[_-]?key/gi, type: "SendGrid Key", severity: "high" },
  { pattern: /mailgun[_-]?api[_-]?key/gi, type: "Mailgun Key", severity: "high" },
  { pattern: /firebase[_-]?api[_-]?key/gi, type: "Firebase Key", severity: "high" },
  { pattern: /google[_-]?apis[_-]?key/gi, type: "Google API Key", severity: "high" },
  { pattern: /AIza[0-9A-Za-z_-]{35}/g, type: "Google API Key", severity: "high" },
  { pattern: /[0-9a-fA-F]{32}/g, type: "Potential Secret (32 hex)", severity: "medium" },
  { pattern: /[0-9a-fA-F]{40}/g, type: "Potential Secret (40 hex)", severity: "medium" },
];

const VULNERABILITY_RULES = [
  { pattern: /eval\s*\(/g, severity: "critical", title: "Dangerous eval() Usage", description: "eval() can execute arbitrary code. Avoid using it with user input.", fix: "Use JSON.parse() or a safe parsing library.", category: "Code Injection" },
  { pattern: /exec\s*\(/g, severity: "critical", title: "Dangerous exec() Usage", description: "exec() executes shell commands. Can be exploited for code injection.", fix: "Avoid exec(). Use subprocess with argument lists.", category: "Code Injection" },
  { pattern: /__import__\s*\(\s*["']os["']\s*\)/g, severity: "high", title: "Dynamic Module Import", description: "Dynamic imports can be used to bypass security checks.", fix: "Use static imports only.", category: "Code Injection" },
  { pattern: /pickle\.loads\s*\(/g, severity: "critical", title: "Insecure Deserialization (pickle)", description: "pickle can execute arbitrary code during deserialization.", fix: "Use json or MessagePack instead.", category: "Insecure Deserialization" },
  { pattern: /yaml\.load\s*\(/g, severity: "high", title: "Insecure YAML Parsing", description: "yaml.load can execute arbitrary code.", fix: "Use yaml.safe_load() or yaml.safe_load_all().", category: "Code Injection" },
  { pattern: /subprocess\.\w*\(\s*shell\s*=\s*True/g, severity: "critical", title: "Shell Injection Risk", description: "shell=True allows shell command injection.", fix: "Set shell=False and use argument lists.", category: "Command Injection" },
  { pattern: /os\.system\s*\(/g, severity: "high", title: "os.system() Usage", description: "os.system() is vulnerable to command injection.", fix: "Use subprocess.run() with argument lists.", category: "Command Injection" },
  { pattern: /os\.popen\s*\(/g, severity: "high", title: "os.popen() Usage", description: "os.popen() can be exploited for command injection.", fix: "Use subprocess.run() instead.", category: "Command Injection" },
  { pattern: /child_process\.\w*\(\s*\{[^}]*shell\s*:\s*true/g, severity: "critical", title: "Node.js Shell Injection", description: "shell option enables command injection.", fix: "Use execFile with arguments array.", category: "Command Injection" },
  { pattern: /\.\s*innerHTML\s*=/g, severity: "high", title: "Potential XSS", description: "Direct innerHTML can lead to XSS attacks.", fix: "Use textContent or sanitize HTML.", category: "XSS" },
  { pattern: /dangerouslySetInnerHTML/g, severity: "high", title: "React XSS Risk", description: "dangerouslySetInnerHTML can lead to XSS.", fix: "Sanitize HTML or use a safer alternative.", category: "XSS" },
  { pattern: /document\.write\s*\(/g, severity: "medium", title: "document.write() Usage", description: "document.write() can lead to XSS and is deprecated.", fix: "Use DOM manipulation methods instead.", category: "XSS" },
  { pattern: /WHERE\s+\w+\s*=\s*["'][^"']*\%s["']|WHERE\s+\w+\s*=\s*f["']/gi, severity: "critical", title: "SQL Injection", description: "String concatenation in SQL allows injection.", fix: "Use parameterized queries.", category: "SQL Injection" },
  { pattern: /cursor\.execute\s*\(\s*["'][^"']*\%s["']/gi, severity: "critical", title: "SQL Injection Risk", description: "SQL query uses string formatting.", fix: "Use parameterized queries with placeholders.", category: "SQL Injection" },
  { pattern: /\.format\s*\(\s*["'][^"']*\{/g, severity: "high", title: "SQL Injection via format()", description: "String format in SQL query allows injection.", fix: "Use parameterized queries.", category: "SQL Injection" },
  { pattern: /f["'][^"']*SELECT.*FROM/gi, severity: "critical", title: "SQL Injection via f-string", description: "f-string in SQL allows injection.", fix: "Use parameterized queries.", category: "SQL Injection" },
  { pattern: /dangerouslySetInnerHTML|mark\s*_\s*safe/gi, severity: "high", title: "Unsafe HTML Rendering", description: "Marking HTML as safe can lead to XSS.", fix: "Use safe rendering functions.", category: "XSS" },
  { pattern: /process\.env\[/g, severity: "low", title: "Environment Variable Access", description: "Direct env access without validation.", fix: "Consider validation and defaults.", category: "Best Practice" },
  { pattern: /Math\.random\s*\(\s*\)/g, severity: "medium", title: "Insecure Random", description: "Math.random is not cryptographically secure.", fix: "Use crypto.randomUUID() or crypto.getRandomValues().", category: "Insecure Cryptography" },
  { pattern: /crypto\.createHash\s*\(\s*["']md5["']/g, severity: "high", title: "Weak Cryptography (MD5)", description: "MD5 is cryptographically broken.", fix: "Use SHA-256 or stronger.", category: "Insecure Cryptography" },
  { pattern: /crypto\.createHash\s*\(\s*["']sha1["']/g, severity: "high", title: "Weak Cryptography (SHA1)", description: "SHA1 is cryptographically weak.", fix: "Use SHA-256 or stronger.", category: "Insecure Cryptography" },
  { pattern: /new\s+RegExp\s*\(\s*user/gi, severity: "medium", title: "Regex DoS Risk (ReDoS)", description: "User-controlled regex can cause denial of service.", fix: "Use safe regex patterns or libraries.", category: "Denial of Service" },
  { pattern: /\.join\s*\(\s*["'][^"']+\+\s*/g, severity: "low", title: "String Concatenation in Join", description: "Inefficient string concatenation.", fix: "Use template literals or join properly.", category: "Best Practice" },
  { pattern: /fetch\s*\(\s*url\s*,?\s*\{[^}]*credentials\s*:\s*["']include["']/g, severity: "high", title: "Credential Leakage Risk", description: "fetch with credentials:include sends cookies to all origins.", fix: "Specify exact origins or use CSRF tokens.", category: "Access Control" },
  { pattern: /Access-Control-Allow-Origin\s*:\s*["']\*["']/g, severity: "high", title: "CORS Misconfiguration", description: "Allowing all origins is a security risk.", fix: "Specify exact allowed origins.", category: "Access Control" },
  { pattern: /withCredentials\s*:\s*true/g, severity: "medium", title: "CORS Risk", description: "Credentials sent to all origins.", fix: "Restrict CORS to specific origins.", category: "Access Control" },
  { pattern: /permit\s*\(\s*\{\s*[^}]*all\s*:\s*true/gi, severity: "high", title: "Mass Assignment", description: "Allowing all fields in deserialization is risky.", fix: "Explicitly define allowed fields.", category: "Access Control" },
  { pattern: /assert\s*\(/g, severity: "low", title: "Assert in Production", description: "Assert statements are removed in optimized code.", fix: "Use explicit validation.", category: "Best Practice" },
  { pattern: /console\.(log|debug|info)\s*\(/g, severity: "low", title: "Debug Statement Left", description: "Debug logging in production.", fix: "Use proper logging levels.", category: "Best Practice" },
  { pattern: /print\s*\(/g, severity: "low", title: "Print Statement in Code", description: "print() statement left in code.", fix: "Remove or use proper logging.", category: "Best Practice" },
  { pattern: /password\s*=\s*input\s*\(\s*type\s*=\s*["']text["']/gi, severity: "medium", title: "Plain Text Password Input", description: "Password input should have type='password'.", fix: "Use type='password' for password fields.", category: "敏感信息泄露" },
  { pattern: /session\s*\.\s*store|express-session|cookie-session/g, severity: "low", title: "Session Management", description: "Session handling detected.", fix: "Ensure secure session configuration.", category: "Session Management" },
  { pattern: /jwt\.decode|jsonwebtoken/gi, severity: "low", title: "JWT Usage", description: "JWT library detected - verify signatures!", fix: "Always verify JWT signatures.", category: "Authentication" },
  { pattern: /bcrypt\.hash\s*\(\s*\)/gi, severity: "low", title: "Password Hashing", description: "Password hashing detected.", fix: "Ensure high iteration count (10+).", category: "Authentication" },
  { pattern: /\.pyc|\.pyo|__pycache__/g, severity: "low", title: "Python Cache File", description: "Python cache files committed.", fix: "Add to .gitignore.", category: "Configuration" },
  { pattern: /\.env(?!\s)|\.env\./g, severity: "low", title: "Environment File", description: "Environment file detected.", fix: "Ensure .env is in .gitignore.", category: "Configuration" },
  { pattern: /debug\s*=\s*True/gi, severity: "high", title: "Debug Mode Enabled", description: "Debug mode is enabled in production.", fix: "Set DEBUG=False in production.", category: "Configuration" },
  { pattern: /cors\.\w*\*\(/g, severity: "high", title: "Permissive CORS", description: "CORS allowing all origins.", fix: "Restrict to specific domains.", category: "Access Control" },
  { pattern: /urlopen|urllib\.request/gi, severity: "medium", title: "Insecure URL Library", description: "Using urllib directly.", fix: "Use requests with verification.", category: "Transport Security" },
  { pattern: /verify\s*=\s*False/g, severity: "high", title: "Certificate Verification Disabled", description: "SSL verification disabled.", fix: "Set verify=True for production.", category: "Transport Security" },
  { pattern: /disable[_-]?[_-]?(web|api)[_-]?browsing[_-]?security/gi, severity: "high", title: "Security Header Missing", description: "Web security headers not set.", fix: "Use security middleware.", category: "Security Headers" },
  { pattern: /x[_-]?frame[_-]?options/gi, severity: "medium", title: "Clickjacking Protection", description: "X-Frame-Options not set.", fix: "Set to DENY or SAMEORIGIN.", category: "Security Headers" },
  { pattern: /content[_-]?security[_-]?policy/gi, severity: "medium", title: "CSP Not Set", description: "Content-Security-Policy not configured.", fix: "Configure CSP properly.", category: "Security Headers" },
];

function scanFile(file: { path: string; content: string; language: string }): Vulnerability[] {
  const findings: Vulnerability[] = [];
  const lines = file.content.split("\n");
  
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNum = i + 1;
    
    for (const rule of VULNERABILITY_RULES) {
      const regex = new RegExp(rule.pattern.source, rule.pattern.flags);
      if (regex.test(line)) {
        findings.push({
          id: `${file.path}:${lineNum}-${findings.length}`,
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
      const regex = new RegExp(secret.pattern.source, secret.pattern.flags);
      if (regex.test(line)) {
        findings.push({
          id: `secret-${file.path}:${lineNum}`,
          severity: secret.severity as "critical" | "high" | "medium" | "low",
          title: `${secret.type} Detected`,
          description: `A ${secret.type.toLowerCase()} was found in the code. This should be stored in environment variables.`,
          file: file.path,
          line: lineNum,
          code: line.trim().substring(0, 80),
          fix: `Move ${secret.type} to environment variables. Use process.env.${secret.type.toUpperCase().replace(/\s/g, '_')} or secrets manager.`,
          category: "Secrets",
        });
      }
    }
  }
  
  return findings;
}

async function checkDependencies(
  repoName: string, 
  files: Array<{ path: string; content: string; language: string }>,
  headers: Record<string, string>
): Promise<Vulnerability[]> {
  const vulns: Vulnerability[] = [];
  
  const pkgPatterns = [
    { file: "requirements.txt", ecosystem: "pip", pattern: /^([a-zA-Z0-9_-]+)(?:[=<>!~])/ },
    { file: "package.json", ecosystem: "npm", pattern: /"dependencies":\s*\{([^}]+)\}/ },
    { file: "Pipfile", ecosystem: "pip", pattern: /^packages\s*=\s*\[([^]]+)\]/ },
    { file: "pyproject.toml", ecosystem: "pip", pattern: /dependencies\s*=\s*\[([^]]+)\]/ },
    { file: "setup.py", ecosystem: "pip", pattern: /install_requires\s*=\s*\[([^]]+)\]/ },
  ];
  
  try {
    const pkgFile = files.find(f => f.path === "requirements.txt" || f.path === "package.json");
    
    if (pkgFile) {
      const pkgs = extractPackages(pkgFile.content);
      
      for (const pkg of pkgs.slice(0, 10)) {
        try {
          const advisoriesRes = await fetch(
            `https://api.github.com/advisories?ecosystem=${pkg.ecosystem}&package=${pkg.name}`,
            { headers }
          );
          
          if (advisoriesRes.ok) {
            const advisories = await advisoriesRes.json();
            
            if (Array.isArray(advisories) && advisories.length > 0) {
              for (const adv of advisories.slice(0, 3)) {
                vulns.push({
                  id: `dep-${pkg.name}-${adv.ghsa_id || Math.random()}`,
                  severity: (adv.severity === "critical" ? "critical" : adv.severity === "high" ? "high" : "medium") as any,
                  title: `Vulnerable Dependency: ${pkg.name}`,
                  description: `${adv.summary || "Known vulnerability in dependency"} (GHSA: ${adv.ghsa_id})`,
                  file: pkgFile.path,
                  line: 1,
                  code: `${pkg.name}@${pkg.version}`,
                  fix: `Update ${pkg.name} to latest version. Check advisory for fix.`,
                  category: "Vulnerable Dependency",
                });
              }
            }
          }
        } catch (e) {
          // Skip failed advisory lookups
        }
      }
    }
  } catch (e) {
    // Return empty if dependency check fails
  }
  
  return vulns;
}

function extractPackages(content: string): Array<{ name: string; version: string; ecosystem: string }> {
  const packages: Array<{ name: string; version: string; ecosystem: string }> = [];
  
  const pipMatch = content.match(/^([a-zA-Z0-9_-]+)(?:[=<>!~])([^\s#]+)/gm);
  if (pipMatch) {
    for (const m of pipMatch.slice(0, 20)) {
      const parts = m.split(/[=<>!~]/);
      if (parts[0] && parts[1]) {
        packages.push({ name: parts[0], version: parts[1], ecosystem: "pip" });
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
  
  // Cap deductions to not be overly harsh for large repos
  deductions = Math.min(deductions, 85);
  
  return Math.max(0, 100 - deductions);
}

function calculateGrade(score: number): string {
  if (score >= 90) return "A";
  if (score >= 75) return "B";
  if (score >= 60) return "C";
  if (score >= 40) return "D";
  return "F";
}