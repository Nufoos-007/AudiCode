import type { VercelRequest, VercelResponse } from "@vercel/node";

export default async function handler(
  request: VercelRequest,
  response: VercelResponse
) {
  if (request.method !== "POST") {
    return response.status(405).json({ error: "Method not allowed" });
  }

  const { repoUrl, token } = request.body;

  if (!repoUrl) {
    return response.status(400).json({ error: "Missing repoUrl" });
  }

  try {
    // Extract owner/repo from URL
    const match = repoUrl.match(/github\.com[/:]([^/]+)\/([^/.]+)/);
    if (!match) {
      return response.status(400).json({ error: "Invalid GitHub URL" });
    }

    const [_, owner, repo] = match;
    const repoName = `${owner}/${repo}`;

    // Fetch repo contents via GitHub API
    const headers: Record<string, string> = {
      Accept: "application/vnd.github.v3+json",
    };

    if (token) {
      headers.Authorization = `token ${token}`;
    }

    // Get repo info
    const repoRes = await fetch(`https://api.github.com/repos/${repoName}`, {
      headers,
    });

    if (!repoRes.ok) {
      if (repoRes.status === 404) {
        return response.status(404).json({ error: "Repository not found" });
      }
      if (repoRes.status === 403) {
        return response.status(403).json({ error: "Rate limited. Add a GitHub token." });
      }
      return response.status(400).json({ error: "Failed to fetch repo" });
    }

    const repoData = await repoRes.json();

    // Get default branch contents for basic scanning
    const contentsRes = await fetch(
      `https://api.github.com/repos/${repoName}/contents?ref=${repoData.default_branch}`,
      { headers }
    );

    let files: Array<{ path: string; content: string; language: string }> = [];

    if (contentsRes.ok) {
      const contents = await contentsRes.json();
      
      // Fetch each file (limit to first 20 for performance)
      const fileList = Array.isArray(contents) ? contents.slice(0, 20) : [];
      
      for (const file of fileList) {
        if (file.type === "file" && file.size < 100000) { // < 100KB
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

    // Basic vulnerability scanning
    const vulnerabilities = scanForVulnerabilities(files);

    const result = {
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
        vulnerabilities,
        score: calculateScore(vulnerabilities),
        grade: calculateGrade(vulnerabilities),
      },
    };

    return response.status(200).json(result);
  } catch (error: any) {
    console.error("Scan error:", error);
    return response.status(500).json({ error: "Scan failed" });
  }
}

function getLanguage(filename: string): string {
  const ext = filename.split(".").pop()?.toLowerCase();
  const langMap: Record<string, string> = {
    js: "JavaScript",
    jsx: "JavaScript",
    ts: "TypeScript",
    tsx: "TypeScript",
    py: "Python",
    rb: "Ruby",
    go: "Go",
    rs: "Rust",
    java: "Java",
    kt: "Kotlin",
    swift: "Swift",
    php: "PHP",
    html: "HTML",
    css: "CSS",
    json: "JSON",
    yaml: "YAML",
    yml: "YAML",
  };
  return langMap[ext || ""] || "Unknown";
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
}

function scanForVulnerabilities(files: Array<{ path: string; content: string; language: string }>): Vulnerability[] {
  const vulnerabilities: Vulnerability[] = [];

  const patterns: Array<{
    pattern: RegExp;
    severity: "critical" | "high" | "medium" | "low";
    title: string;
    description: string;
    fix: string;
  }> = [
    {
      pattern: /eval\s*\(\s*[\$\w]+\s*\)/g,
      severity: "critical",
      title: "Dangerous eval() usage",
      description: "eval() can execute arbitrary code. Avoid using it with user input.",
      fix: "Use JSON.parse() or a safe parsing library instead.",
    },
    {
      pattern: /password\s*=\s*["'][^"']+["']/gi,
      severity: "high",
      title: "Hardcoded password",
      description: "Credentials should not be hardcoded in source code.",
      fix: "Use environment variables or a secrets manager.",
    },
    {
      pattern: /api[_-]?key\s*=\s*["'][^"']+["']/gi,
      severity: "high",
      title: "Hardcoded API key",
      description: "API keys should not be hardcoded in source code.",
      fix: "Use environment variables.",
    },
    {
      pattern: /secret[_-]?key\s*=\s*["'][^"']+["']/gi,
      severity: "high",
      title: "Hardcoded secret key",
      description: "Secret keys should not be hardcoded in source code.",
      fix: "Use environment variables.",
    },
    {
      pattern: /token\s*=\s*["'][^"']+["']/gi,
      severity: "high",
      title: "Hardcoded token",
      description: "Tokens should not be hardcoded in source code.",
      fix: "Use environment variables.",
    },
    {
      pattern: /WHERE\s+\w+\s*=\s*['"][^'"]*\{\s*\w+\s*\}/gi,
      severity: "critical",
      title: "SQL Injection vulnerability",
      description: "String concatenation in SQL queries allows injection attacks.",
      fix: "Use parameterized queries or an ORM.",
    },
    {
      pattern: /shell\s*=\s*True/g,
      severity: "high",
      title: "Shell injection risk",
      description: "shell=True allows shell command injection.",
      fix: "Set shell=False and use argument lists.",
    },
    {
      pattern: /os\.system\s*\(/g,
      severity: "high",
      title: "os.system() usage",
      description: "os.system() can be exploited for command injection.",
      fix: "Use subprocess.run() with argument lists.",
    },
    {
      pattern: /exec\s*\(/g,
      severity: "critical",
      title: " Dangerous exec() usage",
      description: "exec() can execute arbitrary code.",
      fix: "Avoid eval() and exec().",
    },
    {
      pattern: /innerHTML\s*=\s*[\$\w]+/g,
      severity: "medium",
      title: "Potential XSS via innerHTML",
      description: "Directly setting innerHTML can lead to XSS attacks.",
      fix: "Use textContent or sanitize input.",
    },
    {
      pattern: /dangerouslySetInnerHTML/g,
      severity: "medium",
      title: "React dangerouslySetInnerHTML",
      description: "Using dangerouslySetInnerHTML can lead to XSS.",
      fix: "Sanitize HTML or use a safer alternative.",
    },
  ];

  for (const file of files) {
    const lines = file.content.split("\n");
    
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      
      for (const p of patterns) {
        // Reset regex lastIndex
        const regex = new RegExp(p.pattern.source, p.pattern.flags);
        
        if (regex.test(line)) {
          vulnerabilities.push({
            id: `vuln-${vulnerabilities.length + 1}`,
            severity: p.severity,
            title: p.title,
            description: p.description,
            file: file.path,
            line: i + 1,
            code: line.trim().substring(0, 100),
            fix: p.fix,
          });
        }
      }
    }
  }

  return vulnerabilities;
}

function calculateScore(vulnerabilities: Vulnerability[]): number {
  const weights = { critical: 50, high: 25, medium: 10, low: 5 };
  
  let deductions = 0;
  for (const v of vulnerabilities) {
    deductions += weights[v.severity];
  }
  
  return Math.max(0, 100 - deductions);
}

function calculateGrade(vulnerabilities: Vulnerability[]): string {
  const score = calculateScore(vulnerabilities);
  
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 70) return "C";
  if (score >= 60) return "D";
  return "F";
}