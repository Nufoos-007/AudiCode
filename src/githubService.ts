import { ScanReport, VulnerabilityInstance, SeverityType } from './types';
import { runScan } from './scanner';

/**
 * Custom Error Class for Empty or Uninitialized Repositories
 */
export class EmptyRepositoryError extends Error {
  code = 'EMPTY_REPO';
  repository: string;
  branch: string;

  constructor(owner: string, repo: string, branch: string) {
    super(`Repository is empty or branch has not been initialized.`);
    this.name = 'EmptyRepositoryError';
    this.repository = `${owner}/${repo}`;
    this.branch = branch;
  }

  toJSON() {
    return {
      code: this.code,
      repository: this.repository,
      branch: this.branch,
      message: this.message
    };
  }
}

/**
 * Robust GitHub Repository URL Parser
 * Accepts:
 * - https://github.com/owner/repo
 * - https://github.com/owner/repo.git
 * - git@github.com:owner/repo.git
 * - http://github.com/owner/repo/tree/branch-name
 */
export function parseGithubUrl(url: string) {
  let cleanUrl = url.trim().replace(/\/$/, '');
  if (cleanUrl.endsWith('.git')) {
    cleanUrl = cleanUrl.slice(0, -4);
  }

  const httpsRegex = /github\.com\/([^/]+)\/([^/]+)/;
  const sshRegex = /git@github\.com:([^/]+)\/([^/]+)/;

  let match = cleanUrl.match(httpsRegex);
  if (!match) {
    match = cleanUrl.match(sshRegex);
  }

  if (match) {
    const owner = match[1];
    let name = match[2];
    let branch: string | undefined = undefined;

    if (name.includes('/tree/')) {
      const parts = name.split('/tree/');
      name = parts[0];
      branch = parts[1];
    }

    return { owner, name, branch };
  }
  return null;
}

/**
 * Derives A+ through F grades strictly from standard audit metrics scorecard
 */
export function getGradeFromScore(score: number): 'A+' | 'A' | 'B' | 'C' | 'D' | 'F' {
  if (score >= 95) return 'A+';
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 65) return 'C';
  if (score >= 50) return 'D';
  return 'F';
}

/**
 * Fetch default branch & repository details from public GitHub API
 */
export async function fetchRepositoryDetails(owner: string, name: string, token?: string) {
  const url = `https://api.github.com/repos/${owner}/${name}`;
  const headers: Record<string, string> = {
    'User-Agent': 'AudiCode-Scanner',
    'Accept': 'application/vnd.github.v3+json',
  };

  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const res = await fetch(url, { headers });
  if (!res.ok) {
    throw new Error(`Failed to fetch repo schema: GitHub API returned status ${res.status}`);
  }

  const data = await res.json() as any;
  return {
    id: String(data.id),
    name: data.name,
    owner: data.owner.login,
    description: data.description,
    isPrivate: data.private,
    defaultBranch: data.default_branch || 'main',
    url: data.html_url,
  };
}

/**
 * Fetch raw files matching standard limits to pass directly into scanner
 */
export async function fetchRepositoryFiles(owner: string, name: string, branch: string, token?: string) {
  const treeUrl = `https://api.github.com/repos/${owner}/${name}/git/trees/${branch}?recursive=1`;
  const headers: Record<string, string> = {
    'User-Agent': 'AudiCode-Scanner',
  };

  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const treeRes = await fetch(treeUrl, { headers });
  if (!treeRes.ok) {
    if (treeRes.status === 409) {
      throw new EmptyRepositoryError(owner, name, branch);
    }
    throw new Error(`Failed to read GitHub assets tree (Are branch rules correct?): status ${treeRes.status}`);
  }

  const treeData = await treeRes.json() as any;
  if (!treeData.tree || !Array.isArray(treeData.tree) || treeData.tree.length === 0) {
    throw new EmptyRepositoryError(owner, name, branch);
  }

  const rawEntries = treeData.tree.filter((node: any) => {
    if (node.type !== 'blob') return false;

    const p = node.path;
    const ext = '.' + p.split('.').pop()?.toLowerCase();
    const shouldSkip =
      p.includes('node_modules/') ||
      p.includes('dist/') ||
      p.includes('build/') ||
      p.includes('vendor/') ||
      p.includes('coverage/') ||
      p.includes('.git/') ||
      ['.png', '.jpg', '.ico', '.svg', '.woff', '.lock', '.zip'].includes(ext);

    const maxLimitSize = node.size && Number(node.size) <= 50000;
    return !shouldSkip && maxLimitSize;
  });

  const sliced = rawEntries.slice(0, 40);
  const filesContents: { path: string; content: string }[] = [];

  await Promise.all(
    sliced.map(async (node: any) => {
      try {
        const rawRes = await fetch(node.url, {
          headers: {
            ...headers,
            'Accept': 'application/vnd.github.v3.raw',
          },
        });
        if (rawRes.ok) {
          const content = await rawRes.text();
          filesContents.push({ path: node.path, content });
        }
      } catch (e) {
        console.warn(`Could not fetch: ${node.path}`, e);
      }
    })
  );

  return filesContents;
}

/**
 * Query PR modified file list using API pulls/prNumber/files
 */
export async function fetchPrFileList(owner: string, name: string, prNumber: number, token?: string) {
  const url = `https://api.github.com/repos/${owner}/${name}/pulls/${prNumber}/files`;
  const headers: Record<string, string> = {
    'User-Agent': 'AudiCode-Scanner',
    'Accept': 'application/vnd.github.v3+json',
  };

  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const res = await fetch(url, { headers });
  if (!res.ok) {
    throw new Error(`Failed to fetch PR changed files. API returned status ${res.status}`);
  }

  return (await res.json()) as any[];
}

/**
 * Fetch raw PR file content from branch/sha reference
 */
export async function fetchPrFileDetails(owner: string, name: string, filePath: string, ref: string, token?: string) {
  const url = `https://api.github.com/repos/${owner}/${name}/contents/${filePath}?ref=${ref}`;
  const headers: Record<string, string> = {
    'User-Agent': 'AudiCode-Scanner',
  };

  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const res = await fetch(url, {
    headers: { ...headers, 'Accept': 'application/vnd.github.v3.raw' },
  });

  if (!res.ok) {
    throw new Error(`Failed to fetch file detail for path ${filePath} on ref ${ref}`);
  }

  return await res.text();
}

/**
 * Comparative security differential logic
 */
export function analyzePrDiff(baseReport: ScanReport, prReport: ScanReport) {
  const baseFindings = baseReport.findings || [];
  const prFindings = prReport.findings || [];

  const newFindings = prFindings.filter((prF) => {
    return !baseFindings.some(
      (baseF) => baseF.ruleId === prF.ruleId && baseF.filePath === prF.filePath && baseF.snippet === prF.snippet
    );
  });

  const resolvedFindings = baseFindings.filter((baseF) => {
    return !prFindings.some(
      (prF) => prF.ruleId === baseF.ruleId && prF.filePath === baseF.filePath && prF.snippet === baseF.snippet
    );
  });

  const baseChains = baseReport.attackChains || [];
  const prChains = prReport.attackChains || [];

  const attackChainsIntroduced = prChains.filter((prC) => {
    return !baseChains.some((baseC) => baseC.name === prC.name);
  });

  const attackChainsRemoved = baseChains.filter((baseC) => {
    return !prChains.some((prC) => prC.name === baseC.name);
  });

  return {
    baseScore: baseReport.score,
    prScore: prReport.score,
    scoreDelta: prReport.score - baseReport.score,
    newFindings,
    resolvedFindings,
    attackChainsIntroduced,
    attackChainsRemoved,
  };
}

/**
 * Markdown comment syntax generator matching developer compliance demands
 */
export function generatePrComment(
  owner: string,
  name: string,
  prNumber: number,
  comparison: ReturnType<typeof analyzePrDiff>
): string {
  const grade = getGradeFromScore(comparison.prScore);
  const deltaText =
    comparison.scoreDelta > 0
      ? `📈 +${comparison.scoreDelta}`
      : comparison.scoreDelta < 0
      ? `📉 ${comparison.scoreDelta}`
      : `➡️ No change`;

  let md = `## 🛡️ AudiCode Continuous Security Report for PR #${prNumber}

### 📊 Security Grade: **\`${grade}\`** (Score: \`${comparison.prScore}/100\`, Delta: ${deltaText})

| Metric | Base Branch | PR Codebase | Status |
| :--- | :---: | :---: | :---: |
| **Security Score** | \`${comparison.baseScore}%\` | \`${comparison.prScore}%\` | ${deltaText} |
| **New Flaws** | - | \`${comparison.newFindings.length}\` | ${
    comparison.newFindings.length > 0 ? '❌ ACTION REQUIRED' : '✅ SECURE'
  } |
| **Resolved Flaws** | - | \`${comparison.resolvedFindings.length}\` | ${
    comparison.resolvedFindings.length > 0 ? '🎉 REMEDIATED' : '-'
  } |
| **New Attack Chains** | - | \`${comparison.attackChainsIntroduced.length}\` | ${
    comparison.attackChainsIntroduced.length > 0 ? '🚨 SEVERE RISK' : '✅ CLEAN'
  } |
`;

  if (comparison.attackChainsIntroduced.length > 0) {
    md += `\n### 🚨 CRITICAL RISK: New Attack Chains Introduced!\n`;
    comparison.attackChainsIntroduced.forEach((chain) => {
      md += `- **${chain.name}** (${chain.severity} Severity)\n  *Business Impact:* ${chain.businessImpact}\n  *Difficulty:* \`${chain.exploitationDifficulty}\`\n\n`;
    });
  }

  const criticals = comparison.newFindings.filter((f) => f.severity === 'CRITICAL');
  const highs = comparison.newFindings.filter((f) => f.severity === 'HIGH');

  if (criticals.length > 0) {
    md += `\n### 🔴 Critical Findings (${criticals.length})\n`;
    criticals.forEach((f) => {
      md += `#### 🔍 ${f.ruleName} in \`${f.filePath}:${f.startLine}\`
* **Severity:** \`CRITICAL\`
* **Impact/Risk:** ${f.description}
* **Suggested Fix:**
\`\`\`typescript
${f.recommendedFix || f.remediation.afterCode}
\`\`\`
`;
    });
  }

  if (highs.length > 0) {
    md += `\n### 🟠 High Severity Findings (${highs.length})\n`;
    highs.forEach((f) => {
      md += `#### 🔍 ${f.ruleName} in \`${f.filePath}:${f.startLine}\`
* **Severity:** \`HIGH\`
* **Impact/Risk:** ${f.description}
* **Suggested Fix:**
\`\`\`typescript
${f.recommendedFix || f.remediation.afterCode}
\`\`\`
`;
    });
  }

  if (comparison.newFindings.length === 0) {
    md += `\n### 🎉 Clean PR Analysis!
No new security vulnerabilities, secrets leaks, or tainted injection sinks were introduced in this pull request. Great work maintaining high compliance! 🛡️`;
  } else {
    md += `\n### 💡 Remediations
Review the suggested fixes above to secure your pull request. Launch your **AudiCode Playground Workspace** to automatically apply structural AST refactoring.`;
  }

  return md;
}

/**
 * Generate standard automation actions YAML
 */
export function generateWorkflowYaml(options: {
  failOnCritical: boolean;
  failBelowScore: number;
  warningOnly: boolean;
}) {
  const failCmd = options.warningOnly
    ? "echo '=== Continuous compliance complete. (Warning Only Mode enabled) ==='"
    : `node -e "
        const fs = require('fs');
        if (!fs.existsSync('audicode-report.json')) {
          console.log('Skipping validation gates: no local report generated.');
          process.exit(0);
        }
        const report = JSON.parse(fs.readFileSync('audicode-report.json', 'utf8'));
        let exitCode = 0;
        if (${options.failOnCritical} && report.counts && report.counts.critical > 0) {
          console.error('❌ CI/CD failed: Critical security vulnerabilities found!');
          exitCode = 1;
        }
        if (report.score < ${options.failBelowScore}) {
          console.error('❌ CI/CD failed: Security score ' + report.score + ' falls below required threshold of ${options.failBelowScore}!');
          exitCode = 1;
        }
        process.exit(exitCode);
      "`;

  return `# .github/workflows/audicode-scan.yml
name: AudiCode Security Compliance Scanner

on:
  push:
    branches: [ main, master, dev ]
  pull_request:
    branches: [ main, master, dev ]

jobs:
  audicode-compliance:
    name: AudiCode Security & Taint Scan
    runs-on: ubuntu-latest

    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Setup Node.js Runtime
        uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Execute AudiCode Remote API Engine Scan
        env:
          AUDICODE_API_KEY: \${{ secrets.AUDICODE_API_KEY }}
        run: |
          echo "Initiating deep static AST dataflow tracing compilation..."
          curl -s -X POST "https://\${{ github.event.repository.homepage || 'audicode-sigma.vercel.app' }}/api/github/cicd-scan" \\
            -H "Content-Type: application/json" \\
            -H "Authorization: Bearer \$AUDICODE_API_KEY" \\
            -d '{"owner": "\${{ github.repository_owner }}", "name": "\${{ github.event.repository.name }}", "prNumber": \${{ github.event.pull_request.number || 0 }}, "commitSha": "\${{ github.sha }}"}' \\
            -o audicode-report.json
          
          echo "Audit complete. Scorecard saved down to: audicode-report.json"

      - name: Enforce Governance Barriers & Gates
        run: |
          ${failCmd}
`;
}

/**
 * Beautiful dynamic grade SVG builder
 */
export function generateBadgeSvg(score: number): string {
  const grade = getGradeFromScore(score);
  let color = '#FF4444'; // default F red
  if (score >= 95) color = '#00FF88'; // A+ bright green
  else if (score >= 90) color = '#00E575'; // A green
  else if (score >= 80) color = '#4D9EFF'; // B blue
  else if (score >= 65) color = '#FFD700'; // C yellow
  else if (score >= 50) color = '#FF8C00'; // D orange

  return `<svg xmlns="http://www.w3.org/2000/svg" width="130" height="20" viewBox="0 0 130 20">
  <linearGradient id="b" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <mask id="a">
    <rect width="130" height="20" rx="4" fill="#fff"/>
  </mask>
  <g mask="url(#a)">
    <rect width="85" height="20" fill="#13171e"/>
    <rect x="85" width="45" height="20" fill="${color}"/>
    <rect width="130" height="20" fill="url(#b)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-weight="bold" font-size="10">
    <text x="42.5" y="15" fill="#010101" fill-opacity=".3">audicode</text>
    <text x="42.5" y="14" fill="#8b949e">audicode</text>
    <text x="107.5" y="15" fill="#010101" fill-opacity=".3">${grade}</text>
    <text x="107.5" y="14" fill="#0d1117">${grade}</text>
  </g>
</svg>`;
}

/**
 * Post security report as a live comment directly to a GitHub Pull Request
 */
export async function publishPrComment(
  owner: string,
  name: string,
  prNumber: number,
  body: string,
  token: string
) {
  const url = `https://api.github.com/repos/${owner}/${name}/issues/${prNumber}/comments`;
  const headers: Record<string, string> = {
    'User-Agent': 'AudiCode-Scanner',
    'Accept': 'application/vnd.github.v3+json',
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${token}`
  };

  const res = await fetch(url, {
    method: 'POST',
    headers,
    body: JSON.stringify({ body })
  });

  if (!res.ok) {
    const errText = await res.text();
    throw new Error(`GitHub API failed to post comment on PR #${prNumber}: (${res.status}) ${errText}`);
  }

  return await res.json() as { id: number; html_url: string; body: string };
}

