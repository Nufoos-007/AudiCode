import { createClient } from '@supabase/supabase-js';
import pg from 'pg';
import crypto from 'crypto';
import { runScan } from '../src/scanner';
import { ScanReport } from '../src/types';

// Load Supabase configuration
const supabaseUrl = process.env.SUPABASE_URL || '';
const supabaseAnonKey = process.env.SUPABASE_ANON_KEY || '';
const supabase = (supabaseUrl && supabaseAnonKey)
  ? createClient(supabaseUrl, supabaseAnonKey)
  : null;

// Token encryption configuration
const TOKEN_ENCRYPTION_KEY = process.env.TOKEN_ENCRYPTION_KEY || '8e5e89d1b6cfbc829da8c973551db7f7fef405c6d3df393df8a9a8f27cfde2a5';

function decryptToken(encryptedToken: string): string {
  if (!encryptedToken) return '';
  if (encryptedToken === 'demo_token_sandbox_bypass_true') return encryptedToken;
  if (!encryptedToken.includes(':')) return encryptedToken;
  try {
    const parts = encryptedToken.split(':');
    const iv = Buffer.from(parts.shift() || '', 'hex');
    const encryptedText = Buffer.from(parts.join(':'), 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(TOKEN_ENCRYPTION_KEY, 'hex').slice(0, 32), iv);
    let decrypted = decipher.update(encryptedText, undefined, 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch (err) {
    console.error('[Vercel Serverless] Cryptographic decryption failed:', err);
    return encryptedToken;
  }
}

// Database configuration
const databaseUrl = process.env.DATABASE_URL;
let pool: pg.Pool | null = null;
if (databaseUrl) {
  try {
    pool = new pg.Pool({
      connectionString: databaseUrl,
      ssl: databaseUrl.includes('supabase') || databaseUrl.includes('render') || databaseUrl.includes('elephantsql') || databaseUrl.includes('localhost') === false
        ? { rejectUnauthorized: false }
        : undefined
    });
  } catch (err) {
    console.error('[Vercel Serverless] PostgreSQL initialization failed:', err);
  }
}

async function getAuthenticatedUser(req: any): Promise<any> {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.substring(7) : '';

  const activeSbToken = token || (req.query && req.query.sb_access_token);

  if (activeSbToken === 'demo_token_sandbox_bypass_true' || (req.cookies && req.cookies.audi_sandbox === 'true')) {
    return {
      id: 'guest-dev',
      login: 'demo-auditor',
      name: 'Sandbox Auditor',
      avatarUrl: '',
      accessToken: 'demo_token_sandbox_bypass_true',
      isSandbox: true
    };
  }

  if (!activeSbToken) {
    return null;
  }

  if (!supabase) {
    console.error('[Vercel Serverless] Supabase is not configured.');
    return null;
  }

  try {
    const { data: { user }, error } = await supabase.auth.getUser(activeSbToken);
    if (error || !user) {
      return null;
    }

    const providerToken = req.headers['x-provider-token'] || (req.query && req.query.sb_provider_token) || '';
    const metadata = user.user_metadata || {};

    return {
      id: user.id,
      login: metadata.preferred_username || metadata.user_name || user.email?.split('@')[0] || 'github_user',
      name: metadata.full_name || metadata.name || metadata.user_name || 'GitHub User',
      avatarUrl: metadata.avatar_url || '',
      accessToken: providerToken,
      isSandbox: false
    };
  } catch (err) {
    console.error('[Vercel Serverless] Token validation failed:', err);
    return null;
  }
}

async function saveReportDetails(report: ScanReport, userLogin: string) {
  if (pool) {
    try {
      await pool.query(
        `INSERT INTO scan_reports (
          id, repository_id, repository_name, repository_owner, scanned_at, time_elapsed_ms, total_files_scanned, score, counts, findings, user_login,
          frameworks_detected, ai_generated_probability, ai_risk_level, ai_architecture_quality, ai_factors_text
        )
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
         ON CONFLICT (id) DO UPDATE SET
           scanned_at = EXCLUDED.scanned_at,
           time_elapsed_ms = EXCLUDED.time_elapsed_ms,
           total_files_scanned = EXCLUDED.total_files_scanned,
           score = EXCLUDED.score,
           counts = EXCLUDED.counts,
           findings = EXCLUDED.findings,
           user_login = EXCLUDED.user_login,
           frameworks_detected = EXCLUDED.frameworks_detected,
           ai_generated_probability = EXCLUDED.ai_generated_probability,
           ai_risk_level = EXCLUDED.ai_risk_level,
           ai_architecture_quality = EXCLUDED.ai_architecture_quality,
           ai_factors_text = EXCLUDED.ai_factors_text`,
        [
          report.id,
          String(report.repositoryId),
          report.repositoryName,
          report.repositoryOwner,
          report.scannedAt,
          report.timeElapsedMs,
          report.totalFilesScanned,
          report.score,
          JSON.stringify(report.counts),
          JSON.stringify(report.findings),
          userLogin,
          JSON.stringify(report.frameworksDetected || []),
          report.aiGeneratedProbability || 0,
          report.aiRiskLevel || 'LOW',
          report.aiArchitectureQuality || 'EXCELLENT',
          JSON.stringify(report.aiFactorsText || [])
        ]
      );
    } catch (err) {
      console.error('[Vercel Serverless] Failed to persist scan report to database:', err);
    }
  }
}

// Stub demo static catalogs
const DEMO_REPOSITORIES = [
  { id: 'demo-auth-service', owner: 'active-sandbox', name: 'go-micro-auth-manager' },
  { id: 'demo-payment-routing', owner: 'active-sandbox', name: 'node-stripe-bypasser' },
  { id: 'demo-ai-agent-v3', owner: 'active-sandbox', name: 'assistant-terminal-agent' }
];

const DEMO_FILES: Record<string, { path: string; content: string }[]> = {
  'demo-auth-service': [
    {
      path: 'main.go',
      content: `package main\nimport "fmt"\n\nfunc main() {\n\t// TODO: Missing database authentication\n\tfmt.Println("Init database without check")\n}`
    },
    {
      path: 'db.go',
      content: `package db\nimport "database/sql"\n\nfunc QueryUser(id string) {\n\tdb.Query("SELECT * FROM users WHERE id = " + id) // SQLI-RAW-GO\n}`
    }
  ],
  'demo-payment-routing': [
    {
      path: 'server.js',
      content: `const express = require('express');\nconst app = express();\n\n// WEB-CORS-OPEN\napp.use((req, res, next) => {\n  res.setHeader('Access-Control-Allow-Origin', '*');\n  next();\n});\n\n// SEC-DEV-CREDENTIALS\nconst apiKey = "sk-proj-55928a8d119c";`
    }
  ],
  'demo-ai-agent-v3': [
    {
      path: 'agent.ts',
      content: `import { exec } from 'child_process';\n\nfunction executePrompt(userPrompt) {\n  // WEB-CMD-INJECTION\n  exec(userPrompt, (err, stdout, stderr) => {\n    console.log(stdout);\n  });\n}`
    }
  ]
};

export default async function handler(req: any, res: any) {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { repositoryId, owner, name, defaultBranch } = req.body || {};

  if (!repositoryId || !owner || !name) {
    return res.status(400).json({ error: 'Missing parameters repository selection.' });
  }

  try {
    const user = await getAuthenticatedUser(req);
    if (!user) {
      return res.status(401).json({ error: 'Session invalid or expired.' });
    }

    // A. Sandbox Mode Handling
    if (user.isSandbox || repositoryId.toString().startsWith('demo-')) {
      const matchingRepoId = repositoryId.toString().startsWith('demo-') ? repositoryId.toString() : 'demo-auth-service';
      const files = DEMO_FILES[matchingRepoId] || DEMO_FILES['demo-auth-service'];
      const activeRepoMeta = DEMO_REPOSITORIES.find(r => r.id === matchingRepoId) || DEMO_REPOSITORIES[0];

      const report = await runScan(files, files.length);
      report.repositoryId = matchingRepoId;
      report.repositoryName = activeRepoMeta.name;
      report.repositoryOwner = activeRepoMeta.owner;

      await saveReportDetails(report, user.login);
      return res.status(200).json({ report });
    }

    // B. Live Github Ingestion
    const branch = defaultBranch || 'main';
    const rawToken = decryptToken(user.accessToken);

    const treeUrl = `https://api.github.com/repos/${owner}/${name}/git/trees/${branch}?recursive=1`;
    const treeResponse = await fetch(treeUrl, {
      headers: {
        'Authorization': `Bearer ${rawToken}`,
        'User-Agent': 'AudiCode-Scanner'
      }
    });

    if (!treeResponse.ok) {
      return res.status(400).json({ error: 'Failed to read repository assets. Verify default branch and token privileges.' });
    }

    const treeData = await treeResponse.json() as any;
    if (!treeData.tree || !Array.isArray(treeData.tree) || treeData.tree.length === 0) {
      return res.status(400).json({ error: 'Repository is empty or accessible directory scope is restricted.' });
    }

    const codeFilesToFetch = treeData.tree.filter((node: any) => {
      if (node.type !== 'blob') return false;
      const p = node.path;
      const ext = '.' + p.split('.').pop()?.toLowerCase();
      const shouldSkip = 
        p.includes('node_modules/') || p.includes('dist/') || p.includes('build/') ||
        p.includes('vendor/') || p.includes('coverage/') || p.includes('.git/') ||
        ext === '.png' || ext === '.jpg' || ext === '.ico' || ext === '.svg' || ext === '.lock';
      
      const maxLimitSize = (node.size && Number(node.size) <= 50000);
      return !shouldSkip && maxLimitSize;
    });

    const activeFileList = codeFilesToFetch.slice(0, 40);
    const filesContents: { path: string; content: string }[] = [];

    await Promise.all(activeFileList.map(async (fileNode: any) => {
      try {
        const fileContentUrl = fileNode.url;
        const blobResponse = await fetch(fileContentUrl, {
          headers: {
            'Authorization': `Bearer ${rawToken}`,
            'User-Agent': 'AudiCode-Scanner',
            'Accept': 'application/vnd.github.v3.raw'
          }
        });

        if (blobResponse.ok) {
          const content = await blobResponse.text();
          filesContents.push({ path: fileNode.path, content });
        }
      } catch (_) {
        // ignore single file fetch failures
      }
    }));

    if (filesContents.length === 0) {
      return res.status(400).json({ error: 'No compatible source code text files under 50KB found.' });
    }

    const report = await runScan(filesContents, codeFilesToFetch.length);
    report.repositoryId = repositoryId;
    report.repositoryName = name;
    report.repositoryOwner = owner;

    await saveReportDetails(report, user.login);
    return res.status(200).json({ report });

  } catch (error: any) {
    console.error('[Vercel Serverless] Scan pipeline failure:', error);
    return res.status(500).json({ error: error.message || 'Internal server error scanning codebase.' });
  }
}
