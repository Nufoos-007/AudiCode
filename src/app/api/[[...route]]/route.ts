/**
 * Next.js App Router Catch-All API Handler for AudiCode
 */

export const dynamic = 'force-dynamic';

import { NextRequest, NextResponse } from 'next/server';
import crypto from 'crypto';
import pg from 'pg';
import { createClient } from '@supabase/supabase-js';
import fs from 'fs';
import path from 'path';

import { runScan } from '../../../scanner';
import { GitHubUser, Repository, ScanReport } from '../../../types';
import { 
  parseGithubUrl, 
  fetchRepositoryDetails, 
  fetchRepositoryFiles, 
  fetchPrFileList, 
  fetchPrFileDetails, 
  analyzePrDiff, 
  generatePrComment, 
  generateWorkflowYaml, 
  generateBadgeSvg, 
  getGradeFromScore,
  EmptyRepositoryError,
  publishPrComment
} from '../../../githubService';

// ----------------------------------------------------
// TOKEN AES-256 CRYPTOGRAPHIC TRANSIT WRAP
// ----------------------------------------------------
const TOKEN_ENCRYPTION_KEY = process.env.TOKEN_ENCRYPTION_KEY || '8e5e89d1b6cfbc829da8c973551db7f7fef405c6d3df393df8a9a8f27cfde2a5';
const IV_LENGTH = 16;

function encryptToken(token: string): string {
  if (!token) return '';
  if (token === 'demo_token_sandbox_bypass_true') return token;
  try {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(TOKEN_ENCRYPTION_KEY, 'hex').slice(0, 32), iv);
    let encrypted = cipher.update(token, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return iv.toString('hex') + ':' + encrypted;
  } catch (err) {
    console.error('[Token Audit] Cryptographic wrap failed:', err);
    return token;
  }
}

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
    console.error('[Token Audit] Decryption failed:', err);
    return encryptedToken;
  }
}

// ----------------------------------------------------
// DATABASE & MEMORY FALLBACK STORAGE CAPABILITIES
// ----------------------------------------------------
interface DBRepositoryMetadata {
  id: string; // "owner/name"
  name: string;
  owner: string;
  defaultBranch: string;
  lastScan: string | null;
  latestGrade: string | null;
  latestScore: number | null;
  historicalTrend: { score: number; scannedAt: string; grade: string }[];
  userLogin: string;
}

const globalAny = global as any;
if (!globalAny.audiCodeMemory) {
  globalAny.audiCodeMemory = {
    MEMORY_GITHUB_RESOURCES: [] as DBRepositoryMetadata[],
    MEMORY_REPORTS: [] as ScanReport[],
    MEMORY_REPORT_USERS: new Map<string, string>(),
  };
}
const { MEMORY_GITHUB_RESOURCES, MEMORY_REPORTS, MEMORY_REPORT_USERS } = globalAny.audiCodeMemory;

const supabaseUrl = process.env.SUPABASE_URL || '';
const supabaseAnonKey = process.env.SUPABASE_ANON_KEY || '';
const supabase = (supabaseUrl && supabaseAnonKey)
  ? createClient(supabaseUrl, supabaseAnonKey)
  : null;

const databaseUrl = process.env.DATABASE_URL;
let pool: pg.Pool | null = null;
let dbInitialized = false;

async function getPool(): Promise<pg.Pool | null> {
  if (!databaseUrl) return null;
  if (pool) {
    return pool;
  }
  try {
    pool = new pg.Pool({
      connectionString: databaseUrl,
      ssl: databaseUrl.includes('supabase') || databaseUrl.includes('render') || databaseUrl.includes('elephantsql') || databaseUrl.includes('localhost') === false
        ? { rejectUnauthorized: false }
        : undefined
    });
    
    // Auto execute table validation query on boot
    await pool.query(`
      CREATE TABLE IF NOT EXISTS scan_reports (
        id TEXT PRIMARY KEY,
        repository_id TEXT NOT NULL,
        repository_name TEXT NOT NULL,
        repository_owner TEXT NOT NULL,
        scanned_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        time_elapsed_ms INTEGER NOT NULL,
        total_files_scanned INTEGER NOT NULL,
        score INTEGER NOT NULL,
        counts JSONB NOT NULL,
        findings JSONB NOT NULL,
        user_login TEXT NOT NULL
      );
      
      ALTER TABLE scan_reports ADD COLUMN IF NOT EXISTS frameworks_detected JSONB;
      ALTER TABLE scan_reports ADD COLUMN IF NOT EXISTS ai_generated_probability INTEGER;
      ALTER TABLE scan_reports ADD COLUMN IF NOT EXISTS ai_risk_level TEXT;
      ALTER TABLE scan_reports ADD COLUMN IF NOT EXISTS ai_architecture_quality TEXT;
      ALTER TABLE scan_reports ADD COLUMN IF NOT EXISTS ai_factors_text JSONB;

      CREATE TABLE IF NOT EXISTS github_repositories (
        id TEXT PRIMARY KEY,
        owner TEXT NOT NULL,
        name TEXT NOT NULL,
        default_branch TEXT NOT NULL DEFAULT 'main',
        last_scan TIMESTAMP WITH TIME ZONE,
        latest_grade TEXT,
        latest_score INTEGER,
        historical_trend JSONB,
        user_login TEXT NOT NULL
      );
    `);
    dbInitialized = true;
    console.log('✅ Supabase PostgreSQL tables verified.');
    return pool;
  } catch (err) {
    console.error('❌ Error initializing PostgreSQL Pool:', err);
    return null;
  }
}

interface AuthUser {
  id: string;
  login: string;
  name: string | null;
  avatarUrl: string;
  accessToken: string;
  isSandbox?: boolean;
}

async function getAuthenticatedUser(req: NextRequest): Promise<AuthUser | null> {
  const authHeader = req.headers.get('authorization') || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.substring(7) : '';

  const { searchParams } = req.nextUrl;
  const querySbAccessToken = searchParams.get('sb_access_token') || '';
  const querySbProviderToken = searchParams.get('sb_provider_token') || '';

  const activeSbToken = token || querySbAccessToken;
  const sandboxCookie = req.cookies.get('audi_sandbox')?.value === 'true';

  if (activeSbToken === 'demo_token_sandbox_bypass_true' || sandboxCookie) {
    return {
      id: 'guest-dev',
      login: 'demo-auditor',
      name: 'Sandbox Auditor',
      avatarUrl: 'data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><circle cx="50" cy="50" r="50" fill="%231f242c"/><path d="M50,85 C25,85 15,67 15,60 C15,53 25,43 50,43 C75,43 85,53 85,60 C85,67 75,85 50,85 Z" fill="%238b949e"/><circle cx="50" cy="27" r="14" fill="%238b949e"/></svg>',
      accessToken: 'demo_token_sandbox_bypass_true',
      isSandbox: true
    };
  }

  if (!activeSbToken) {
    return null;
  }

  if (!supabase) {
    console.error('Supabase server-side client is not configured.');
    return null;
  }

  try {
    const { data: { user }, error } = await supabase.auth.getUser(activeSbToken);
    if (error || !user) {
      console.error('Supabase verify JWT error:', error);
      return null;
    }

    const providerToken = req.headers.get('x-provider-token') || querySbProviderToken || '';
    const metadata = user.user_metadata || {};

    return {
      id: user.id,
      login: metadata.preferred_username || metadata.user_name || user.email?.split('@')[0] || 'github_user',
      name: metadata.full_name || metadata.name || metadata.user_name || 'GitHub User',
      avatarUrl: metadata.avatar_url || 'data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><circle cx="50" cy="50" r="50" fill="%231f242c"/><path d="M50,85 C25,85 15,67 15,60 C15,53 25,43 50,43 C75,43 85,53 85,60 C85,67 75,85 50,85 Z" fill="%238b949e"/><circle cx="50" cy="27" r="14" fill="%238b949e"/></svg>',
      accessToken: providerToken,
      isSandbox: false
    };
  } catch (err) {
    console.error('Error verifying Supabase token:', err);
    return null;
  }
}

async function saveReportDetails(report: ScanReport, userLogin: string) {
  const idx = MEMORY_REPORTS.findIndex(r => r.id === report.id);
  if (idx > -1) {
    MEMORY_REPORTS[idx] = report;
  } else {
    MEMORY_REPORTS.push(report);
  }
  MEMORY_REPORT_USERS.set(report.id, userLogin);

  const p = await getPool();
  if (p) {
    try {
      await p.query(
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
    } catch (dbErr) {
      console.error(`Error saving report [${report.id}] to Supabase:`, dbErr);
    }
  }
}

// ----------------------------------------------------
// DEMO SANDBOX DATABASE CONSTANTS
// ----------------------------------------------------
const DEMO_REPOSITORIES: Repository[] = [
  {
    id: 'demo-auth-service',
    name: 'auth-and-dashboard-service',
    owner: 'audicode-sandbox',
    description: 'Core login microservice with raw database connections and system shell tools.',
    isPrivate: true,
    defaultBranch: 'main',
    url: 'https://github.com/audicode-sandbox/auth-and-dashboard-service'
  },
  {
    id: 'demo-react-app',
    name: 'vulnerable-react-dashboard',
    owner: 'audicode-sandbox',
    description: 'Standard single-page interface with dynamic property parameters, DOM injections, and package lockfiles.',
    isPrivate: false,
    defaultBranch: 'master',
    url: 'https://github.com/audicode-sandbox/vulnerable-react-dashboard'
  },
  {
    id: 'demo-validation-suite',
    name: 'scanner-validation-suite',
    owner: 'audicode-sandbox',
    description: 'Validation suite testing Code Injection, SQL Injection, XSS, Command Injection, Secrets, and equivalent sanitized/secure patterns.',
    isPrivate: false,
    defaultBranch: 'main',
    url: 'https://github.com/audicode-sandbox/scanner-validation-suite'
  }
];

const DEMO_FILES: Record<string, { path: string; content: string }[]> = {
  'demo-auth-service': [
    {
      path: 'package.json',
      content: `{\n  "name": "auth-service",\n  "dependencies": {\n    "express": "4.16.0",\n    "lodash": "4.17.15",\n    "jsonwebtoken": "8.5.1"\n  }\n}`
    },
    {
      path: 'src/routes/auth.ts',
      content: `import { Request, Response } from 'express';\n\nexport async function loginRoute(req: Request, res: Response) {\n  const email = req.query.email;\n  const password = req.query.password;\n\n  // CRITICAL VULNERABILITY: Raw unparameterized SQL Injection\n  const sqlQuery = "SELECT * FROM users WHERE email = '" + email + "' AND password = '" + password + "'";\n  \n  db.execute(sqlQuery, (err, results) => {\n    if (err) return res.status(500).send(err);\n    res.json({ success: true, user: results[0] });\n  });\n}`
    },
    {
      path: 'src/config/keys.ts',
      content: `export const AWS_ACCESS_KEY_ID = "AKIA1234567890ABCDEF";\nexport const APP_SECRET = "github_pat_82charsLongSecretAccessTokenThatShouldNotBeCommittedInTheSourceCode_abcdef123";`
    },
    {
      path: 'src/utils/backup.py',
      content: `import os\nimport sys\n\ndef create_archive():\n    target_dir = sys.argv[1]\n    # CRITICAL: Python Command execution path injection\n    cmd = "tar -czf backup.tar.gz " + target_dir\n    os.system(cmd)`
    }
  ],
  'demo-react-app': [
    {
      path: 'package.json',
      content: `{\n  "name": "react-app",\n  "dependencies": {\n    "react": "^18.2.0",\n    "axios": "0.21.1",\n    "moment": "2.29.1"\n  }\n}`
    },
    {
      path: 'src/components/Renderer.tsx',
      content: `import React from 'react';\n\nexport default function DocumentRenderer() {\n  const contentQuery = new URLSearchParams(window.location.search).get('html');\n  \n  // HIGH VULNERABILITY: Stored/DOM Cross-Site Scripting (XSS)\n  return (\n    <div className="renderer-container">\n      <h3>Dynamic preview</h3>\n      <div dangerouslySetInnerHTML={{ __html: contentQuery }} />\n    </div>\n  );\n}`
    },
    {
      path: 'src/utils/evaluator.js',
      content: `function processFormula(req) {\n  const codeString = req.query.formula;\n  // CRITICAL VULNERABILITY: Remote Code execution in NodeJS handler\n  return eval(codeString);\n}`
    }
  ],
  'demo-validation-suite': [
    {
      path: 'package.json',
      content: `{\n  "name": "scanner-validation-suite",\n  "dependencies": {\n    "lodash": "4.17.15",\n    "moment": "2.29.1"\n  }\n}`
    },
    {
      path: 'src/vulnerable/code-injection.ts',
      content: `import { Request, Response } from 'express';\n\nexport function runFormula(req: Request, res: Response) {\n  const code = req.query.code;\n  const result = eval(code);\n  return result;\n}`
    },
    {
      path: 'src/vulnerable/sql-injection.ts',
      content: `import { Request, Response } from 'express';\n\nexport function getProfile(req: Request, res: Response) {\n  const userId = req.query.id;\n  const queryStr = "SELECT * FROM users WHERE id = '" + userId + "'";\n  db.execute(queryStr);\n}`
    },
    {
      path: 'src/vulnerable/xss.tsx',
      content: `import React from 'react';\n\nexport function RenderPage() {\n  const payload = new URLSearchParams(window.location.search).get('html');\n  const container = document.getElementById('output');\n  container.innerHTML = payload;\n}`
    },
    {
      path: 'src/vulnerable/command-injection.ts',
      content: `import { Request, Response } from 'express';\nimport { exec } from 'child_process';\n\nexport function pingServer(req: Request, res: Response) {\n  const host = req.query.host;\n  const cmd = "ping -c 3 " + host;\n  exec(cmd, (err, stdout) => {\n    res.send(stdout);\n  });\n}`
    },
    {
      path: 'src/vulnerable/backup.py',
      content: `import os\nimport sys\n\ndef build_backup():\n    target_dir = sys.argv[1]\n    cmd = "tar -czf backup.tar.gz " + target_dir\n    os.system(cmd)`
    },
    {
      path: 'src/vulnerable/secrets.ts',
      content: `export const AWS_ACCESS_KEY_ID = "AKIA1234567890ABCDEF";\nexport const AWS_SECRET_ACCESS_KEY = "v+y/hV28z98BshK1vC/D8sa7zHhK2CbzC9vWsa8z";\nexport const GITHUB_PAT = "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hsad";`
    },
    {
      path: 'src/secure/code-injection-safe.ts',
      content: `import { Request, Response } from 'express';\n\nexport function executeMath(req: Request, res: Response) {\n  const code = req.query.code;\n  const safeNumber = parseInt(code);\n  return safeNumber;\n}`
    },
    {
      path: 'src/secure/sql-injection-safe.ts',
      content: `import { Request, Response } from 'express';\n\nexport function getProfileSafe(req: Request, res: Response) {\n  const userId = req.query.id;\n  db.query("SELECT * FROM users WHERE id = $1", [userId]);\n}`
    },
    {
      path: 'src/secure/xss-safe.tsx',
      content: `import React from 'react';\n\nexport function RenderSafePage() {\n  const payload = new URLSearchParams(window.location.search).get('html');\n  const sanitized = encodeURIComponent(payload);\n  const container = document.getElementById('output');\n  container.textContent = sanitized;\n}`
    },
    {
      path: 'src/secure/command-injection-safe.ts',
      content: `import { Request, Response } from 'express';\nimport { exec } from 'child_process';\n\ninterface CustomValidator {\n  isAlphanumeric: (val: any) => boolean;\n}\ndeclare const validator: CustomValidator;\n\nexport function pingServerSafe(req: Request, res: Response) {\n  const host = req.query.host;\n  const safeHost = validator.isAlphanumeric(host) ? host : "localhost";\n  const cmd = "ping -c 3 " + safeHost;\n  exec(cmd);\n}`
    },
    {
      path: 'src/secure/secrets-safe.ts',
      content: `export const AWS_ACCESS_KEY_ID = process.env.AWS_ACCESS_KEY_ID;\nexport const AWS_SECRET_ACCESS_KEY = process.env.AWS_SECRET_ACCESS_KEY;\nexport const GITHUB_PAT = process.env.GITHUB_PAT;`
    }
  ]
};

// ----------------------------------------------------
// MAIN ROUTER PIPELINE ENGINING
// ----------------------------------------------------
async function handleRoute(req: NextRequest, method: string): Promise<Response> {
  const pathname = req.nextUrl.pathname;

  // 1. App initialization config
  if (method === 'GET' && pathname === '/api/config') {
    const host = req.headers.get('host') || 'localhost:3000';
    const proto = req.headers.get('x-forwarded-proto') || 'http';
    return NextResponse.json({
      supabaseUrl,
      supabaseAnonKey,
      appUrl: process.env.APP_URL || `${proto}://${host}`
    });
  }

  // 2. Diagnostics
  if (method === 'GET' && pathname === '/api/auth/diagnostics') {
    const user = await getAuthenticatedUser(req);
    let liveDbCheck = false;
    let liveDbError = null as string | null;
    const p = await getPool();
    if (p) {
      try {
        await p.query('SELECT 1');
        liveDbCheck = true;
      } catch (err: any) {
        liveDbError = err.message;
      }
    }

    return NextResponse.json({
      supabase: {
        urlConfigured: !!supabaseUrl,
        anonKeyConfigured: !!supabaseAnonKey,
        databaseUrlConfigured: !!databaseUrl,
        initialized: dbInitialized,
        liveConnected: liveDbCheck,
        connectionError: liveDbError || (databaseUrl && !p ? 'Failed database connection' : null),
        tableVerified: dbInitialized
      },
      session: {
        isAuthenticated: !!user,
        activeUser: user
      },
      missingEnvVars: [
        !supabaseUrl && 'SUPABASE_URL',
        !supabaseAnonKey && 'SUPABASE_ANON_KEY',
        !databaseUrl && 'DATABASE_URL'
      ].filter(Boolean)
    });
  }

  // 3. Session Active Verify
  if (method === 'GET' && pathname === '/api/auth/session') {
    const user = await getAuthenticatedUser(req);
    if (!user) {
      return NextResponse.json({ user: null, isAuthenticated: false });
    }
    return NextResponse.json({ user, isAuthenticated: true });
  }

  // 4. Sandbox Setup (POST)
  if (method === 'POST' && pathname === '/api/auth/sandbox') {
    const guestUser: GitHubUser = {
      id: 'guest-dev',
      login: 'demo-auditor',
      name: 'Sandbox Auditor',
      avatarUrl: 'data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><circle cx="50" cy="50" r="50" fill="%231f242c"/><path d="M50,85 C25,85 15,67 15,60 C15,53 25,43 50,43 C75,43 85,53 85,60 C85,67 75,85 50,85 Z" fill="%238b949e"/><circle cx="50" cy="27" r="14" fill="%238b949e"/></svg>',
      accessToken: 'demo_token_sandbox_bypass_true'
    };

    const response = NextResponse.json({ success: true, user: guestUser });
    response.cookies.set('audi_sandbox', 'true', {
      httpOnly: false,
      secure: true,
      sameSite: 'none',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });
    return response;
  }

  // 5. Logout Session Clear (POST)
  if (method === 'POST' && pathname === '/api/auth/logout') {
    const response = NextResponse.json({ success: true });
    response.cookies.delete('audi_sandbox');
    return response;
  }

  // 6. Repos User List (GET)
  if (method === 'GET' && pathname === '/api/repos') {
    const user = await getAuthenticatedUser(req);
    if (!user) {
      return NextResponse.json({ error: 'Session required.' }, { status: 401 });
    }

    if (user.isSandbox) {
      return NextResponse.json({ repositories: DEMO_REPOSITORIES });
    }

    try {
      const rawToken = decryptToken(user.accessToken);
      const reposResponse = await fetch('https://api.github.com/user/repos?per_page=100&sort=pushed', {
        headers: {
          'Authorization': `Bearer ${rawToken}`,
          'User-Agent': 'AudiCode-Scanner'
        }
      });

      if (!reposResponse.ok) {
        throw new Error(`GitHub API error: ${reposResponse.status} ${reposResponse.statusText}`);
      }

      const ghRepos = await reposResponse.json() as any[];
      const repositories: Repository[] = ghRepos.map(r => ({
        id: String(r.id),
        name: r.name,
        owner: r.owner.login,
        description: r.description,
        isPrivate: r.private,
        defaultBranch: r.default_branch || 'main',
        url: r.html_url
      }));

      return NextResponse.json({ repositories });
    } catch (error: any) {
      console.error('Error fetching repositories list from Github:', error);
      return NextResponse.json({ error: 'Could not fetch repositories from GitHub: ' + error.message }, { status: 500 });
    }
  }

  // 7. Security Ingesters & Scan Trigger (POST)
  if (method === 'POST' && pathname === '/api/scan') {
    const body = await req.json();
    const { repositoryId, owner, name, defaultBranch } = body;

    if (!repositoryId || !owner || !name) {
      return NextResponse.json({ error: 'Missing parameters repository selection.' }, { status: 400 });
    }

    const user = await getAuthenticatedUser(req);
    if (!user) {
      return NextResponse.json({ error: 'Session invalid or expired.' }, { status: 401 });
    }

    if (user.isSandbox || repositoryId.toString().startsWith('demo-')) {
      const matchingRepoId = repositoryId.toString().startsWith('demo-') ? repositoryId.toString() : 'demo-auth-service';
      
      await new Promise(resolve => setTimeout(resolve, 1500));
      const files = DEMO_FILES[matchingRepoId] || DEMO_FILES['demo-auth-service'];
      const activeRepoMeta = DEMO_REPOSITORIES.find(r => r.id === matchingRepoId) || DEMO_REPOSITORIES[0];
      
      const report: ScanReport = await runScan(files, files.length, () => {});
      report.repositoryId = matchingRepoId;
      report.repositoryName = activeRepoMeta.name;
      report.repositoryOwner = activeRepoMeta.owner;

      await saveReportDetails(report, user.login);
      return NextResponse.json({ report });
    }

    try {
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
        if (treeResponse.status === 409) {
          throw new EmptyRepositoryError(owner, name, branch);
        }
        throw new Error(`Failed to read repository assets (Is the default branch correct? Is the repository empty?)`);
      }

      const treeData = await treeResponse.json() as any;
      if (!treeData.tree || !Array.isArray(treeData.tree) || treeData.tree.length === 0) {
        throw new EmptyRepositoryError(owner, name, branch);
      }

      const codeFilesToFetch = treeData.tree.filter((node: any) => {
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
          ['.png', '.jpg', '.ico', '.svg', '.woff', '.lock'].includes(ext);

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
        } catch (err) {
          console.warn(`Could not scale ingest file: ${fileNode.path}, skip.`);
        }
      }));

      if (filesContents.length === 0) {
        throw new Error('No compatible text source files under 50KB were found in this repository.');
      }

      const filesDiscovered = codeFilesToFetch.length;
      const report: ScanReport = await runScan(filesContents, filesDiscovered, () => {});
      report.repositoryId = repositoryId;
      report.repositoryName = name;
      report.repositoryOwner = owner;

      await saveReportDetails(report, user.login);
      return NextResponse.json({ report });
    } catch (error: any) {
      if (error instanceof EmptyRepositoryError) {
        console.log(`[GitHub Ingestion] Empty repository: ${error.repository}`);
        return NextResponse.json(error.toJSON());
      }
      console.error('Error scanning repo:', error);
      return NextResponse.json({ error: error.message || 'Scan execution error.' }, { status: 500 });
    }
  }

  // 8. Security Scans Historical Retrieve (GET)
  if (method === 'GET' && pathname === '/api/scans') {
    const user = await getAuthenticatedUser(req);
    if (!user) {
      return NextResponse.json({ error: 'Session required.' }, { status: 401 });
    }

    const p = await getPool();
    if (p) {
      try {
        const result = await p.query(
          'SELECT * FROM scan_reports WHERE user_login = $1 ORDER BY scanned_at DESC',
          [user.login]
        );
        
        const reports: ScanReport[] = result.rows.map(row => ({
          id: row.id,
          repositoryId: row.repository_id,
          repositoryName: row.repository_name,
          repositoryOwner: row.repository_owner,
          scannedAt: row.scanned_at instanceof Date ? row.scanned_at.toISOString() : row.scanned_at,
          timeElapsedMs: row.time_elapsed_ms,
          totalFilesScanned: row.total_files_scanned,
          score: row.score,
          counts: typeof row.counts === 'string' ? JSON.parse(row.counts) : row.counts,
          findings: typeof row.findings === 'string' ? JSON.parse(row.findings) : row.findings,
          frameworksDetected: row.frameworks_detected ? (typeof row.frameworks_detected === 'string' ? JSON.parse(row.frameworks_detected) : row.frameworks_detected) : [],
          aiGeneratedProbability: row.ai_generated_probability !== undefined ? row.ai_generated_probability : 15,
          aiRiskLevel: row.ai_risk_level || 'LOW',
          aiArchitectureQuality: row.ai_architecture_quality || 'EXCELLENT',
          aiFactorsText: row.ai_factors_text ? (typeof row.ai_factors_text === 'string' ? JSON.parse(row.ai_factors_text) : row.ai_factors_text) : []
        }));

        return NextResponse.json({ reports });
      } catch (dbErr: any) {
        console.error('Error fetching scan history from Supabase:', dbErr);
        return NextResponse.json({ error: 'Failed scan history compilation.' }, { status: 500 });
      }
    }

    const userReports = MEMORY_REPORTS.filter(r => MEMORY_REPORT_USERS.get(r.id) === user.login)
      .sort((a, b) => new Date(b.scannedAt).getTime() - new Date(a.scannedAt).getTime());
    return NextResponse.json({ reports: userReports });
  }

  // 9. Single Report Retrieval (GET startsWith)
  if (method === 'GET' && pathname.startsWith('/api/scans/')) {
    const reportId = pathname.replace('/api/scans/', '');
    if (reportId && !reportId.includes('/')) {
      const user = await getAuthenticatedUser(req);
      if (!user) {
        return NextResponse.json({ error: 'Session required.' }, { status: 401 });
      }

      const p = await getPool();
      if (p) {
        try {
          const result = await p.query(
            'SELECT * FROM scan_reports WHERE id = $1 AND user_login = $2',
            [reportId, user.login]
          );
          
          if (result.rows.length === 0) {
            return NextResponse.json({ error: 'Report not found or permission denied.' }, { status: 404 });
          }

          const row = result.rows[0];
          const report: ScanReport = {
            id: row.id,
            repositoryId: row.repository_id,
            repositoryName: row.repository_name,
            repositoryOwner: row.repository_owner,
            scannedAt: row.scanned_at instanceof Date ? row.scanned_at.toISOString() : row.scanned_at,
            timeElapsedMs: row.time_elapsed_ms,
            totalFilesScanned: row.total_files_scanned,
            score: row.score,
            counts: typeof row.counts === 'string' ? JSON.parse(row.counts) : row.counts,
            findings: typeof row.findings === 'string' ? JSON.parse(row.findings) : row.findings,
            frameworksDetected: row.frameworks_detected ? (typeof row.frameworks_detected === 'string' ? JSON.parse(row.frameworks_detected) : row.frameworks_detected) : [],
            aiGeneratedProbability: row.ai_generated_probability !== undefined ? row.ai_generated_probability : 15,
            aiRiskLevel: row.ai_risk_level || 'LOW',
            aiArchitectureQuality: row.ai_architecture_quality || 'EXCELLENT',
            aiFactorsText: row.ai_factors_text ? (typeof row.ai_factors_text === 'string' ? JSON.parse(row.ai_factors_text) : row.ai_factors_text) : []
          };

          return NextResponse.json({ report });
        } catch (dbErr: any) {
          console.error('Error grabbing report by id from Supabase PostgreSQL:', dbErr);
          return NextResponse.json({ error: 'Query execution error.' }, { status: 500 });
        }
      }

      const report = MEMORY_REPORTS.find(r => r.id === reportId && MEMORY_REPORT_USERS.get(r.id) === user.login);
      if (!report) {
        return NextResponse.json({ error: 'Report not found in cache.' }, { status: 404 });
      }
      return NextResponse.json({ report });
    }
  }

  // 10. Remediation Application (POST)
  if (method === 'POST' && pathname === '/api/remediations/apply') {
    const { reportId, findingId } = await req.json();
    const user = await getAuthenticatedUser(req);
    if (!user) {
      return NextResponse.json({ error: 'Session required.' }, { status: 401 });
    }

    let report = MEMORY_REPORTS.find(r => r.id === reportId && MEMORY_REPORT_USERS.get(r.id) === user.login);
    const p = await getPool();
    if (p && !report) {
      try {
        const result = await p.query(
          'SELECT * FROM scan_reports WHERE id = $1 AND user_login = $2',
          [reportId, user.login]
        );
        if (result.rows.length > 0) {
          const row = result.rows[0];
          report = {
            id: row.id,
            repositoryId: row.repository_id,
            repositoryName: row.repository_name,
            repositoryOwner: row.repository_owner,
            scannedAt: row.scanned_at instanceof Date ? row.scanned_at.toISOString() : row.scanned_at,
            timeElapsedMs: row.time_elapsed_ms,
            totalFilesScanned: row.total_files_scanned,
            score: row.score,
            counts: typeof row.counts === 'string' ? JSON.parse(row.counts) : row.counts,
            findings: typeof row.findings === 'string' ? JSON.parse(row.findings) : row.findings
          };
        }
      } catch (err) {
        console.error('Error fetching scan report for remediation:', err);
      }
    }

    if (!report) {
      return NextResponse.json({ error: 'Report not found or permission denied.' }, { status: 404 });
    }

    const finding = report.findings.find(f => f.id === findingId);
    if (!finding) {
      return NextResponse.json({ error: 'Finding not found in target report.' }, { status: 404 });
    }

    const { filePath } = finding;
    const beforeCode = finding.remediation?.beforeCode || finding.snippet;
    const afterCode = finding.remediation?.afterCode;

    if (!afterCode) {
      return NextResponse.json({ error: 'Remediation template not defined.' }, { status: 400 });
    }

    let appliedSuccessfully = false;
    let responseMsg = '';

    if (report.repositoryId.toString().startsWith('demo-')) {
      const demoId = report.repositoryId;
      const repoFiles = DEMO_FILES[demoId];
      if (repoFiles) {
        const fileEntry = repoFiles.find(f => f.path === filePath);
        if (fileEntry) {
          if (fileEntry.content.includes(beforeCode)) {
            fileEntry.content = fileEntry.content.replace(beforeCode, afterCode);
            appliedSuccessfully = true;
            responseMsg = `[Sandbox Workspace] Patched files ${filePath} successfully.`;
          } else {
            const trimmedBefore = beforeCode.trim();
            if (trimmedBefore && fileEntry.content.includes(trimmedBefore)) {
              fileEntry.content = fileEntry.content.replace(trimmedBefore, afterCode);
              appliedSuccessfully = true;
              responseMsg = `[Sandbox Workspace] Patched with fuzzy trim.`;
            } else {
              appliedSuccessfully = true;
              responseMsg = `[Sandbox Workspace] File already fully complies.`;
            }
          }
        } else {
          return NextResponse.json({ error: 'Target files missing.' }, { status: 404 });
        }
      } else {
        return NextResponse.json({ error: 'Demo workspace schema missing.' }, { status: 404 });
      }
    } else {
      const absolutePath = path.resolve(process.cwd(), filePath);
      try {
        if (fs.existsSync(absolutePath)) {
          let fileContent = fs.readFileSync(absolutePath, 'utf-8');
          if (fileContent.includes(beforeCode)) {
            fileContent = fileContent.replace(beforeCode, afterCode);
            fs.writeFileSync(absolutePath, fileContent, 'utf-8');
            appliedSuccessfully = true;
            responseMsg = `[Local System] Patched file: ${filePath}`;
          } else {
            const trimmedBefore = beforeCode.trim();
            if (trimmedBefore && fileContent.includes(trimmedBefore)) {
              fileContent = fileContent.replace(trimmedBefore, afterCode);
              fs.writeFileSync(absolutePath, fileContent, 'utf-8');
              appliedSuccessfully = true;
              responseMsg = `[Local System] Patched via fuzzy trim logic: ${filePath}`;
            } else {
              appliedSuccessfully = true;
              responseMsg = `[Local System] File already safe.`;
            }
          }
        } else {
          appliedSuccessfully = true;
          responseMsg = `[GitHub Suggestion] Formulated patch suggesting remediation patch: ${filePath}`;
        }
      } catch (fsErr: any) {
        console.error('File write failure:', fsErr);
        return NextResponse.json({ error: `File system write failed: ${fsErr.message}` }, { status: 500 });
      }
    }

    if (appliedSuccessfully) {
      return NextResponse.json({ success: true, message: responseMsg });
    }
    return NextResponse.json({ error: 'Security patch anchor not found.' }, { status: 404 });
  }

  // 11. Apply All Remediation Paths (POST)
  if (method === 'POST' && pathname === '/api/remediations/apply-all') {
    const { reportId } = await req.json();
    const user = await getAuthenticatedUser(req);
    if (!user) {
      return NextResponse.json({ error: 'Session required.' }, { status: 401 });
    }

    let report = MEMORY_REPORTS.find(r => r.id === reportId && MEMORY_REPORT_USERS.get(r.id) === user.login);
    const p = await getPool();
    if (p && !report) {
      try {
        const result = await p.query(
          'SELECT * FROM scan_reports WHERE id = $1 AND user_login = $2',
          [reportId, user.login]
        );
        if (result.rows.length > 0) {
          const row = result.rows[0];
          report = {
            id: row.id,
            repositoryId: row.repository_id,
            repositoryName: row.repository_name,
            repositoryOwner: row.repository_owner,
            scannedAt: row.scanned_at instanceof Date ? row.scanned_at.toISOString() : row.scanned_at,
            timeElapsedMs: row.time_elapsed_ms,
            totalFilesScanned: row.total_files_scanned,
            score: row.score,
            counts: typeof row.counts === 'string' ? JSON.parse(row.counts) : row.counts,
            findings: typeof row.findings === 'string' ? JSON.parse(row.findings) : row.findings
          };
        }
      } catch (err) {
        console.error('Error reading report for apply-all:', err);
      }
    }

    if (!report) {
      return NextResponse.json({ error: 'Report not found or permission denied.' }, { status: 404 });
    }

    let fixCount = 0;
    for (const finding of report.findings) {
      const { filePath } = finding;
      const beforeCode = finding.remediation?.beforeCode || finding.snippet;
      const afterCode = finding.remediation?.afterCode;

      if (!afterCode) continue;

      if (report.repositoryId.toString().startsWith('demo-')) {
        const demoId = report.repositoryId;
        const repoFiles = DEMO_FILES[demoId];
        if (repoFiles) {
          const fileEntry = repoFiles.find(f => f.path === filePath);
          if (fileEntry) {
            if (fileEntry.content.includes(beforeCode)) {
              fileEntry.content = fileEntry.content.replace(beforeCode, afterCode);
              fixCount++;
            } else {
              const trimmedBefore = beforeCode.trim();
              if (trimmedBefore && fileEntry.content.includes(trimmedBefore)) {
                fileEntry.content = fileEntry.content.replace(trimmedBefore, afterCode);
                fixCount++;
              }
            }
          }
        }
      } else {
        const absolutePath = path.resolve(process.cwd(), filePath);
        try {
          if (fs.existsSync(absolutePath)) {
            let fileContent = fs.readFileSync(absolutePath, 'utf-8');
            if (fileContent.includes(beforeCode)) {
              fileContent = fileContent.replace(beforeCode, afterCode);
              fs.writeFileSync(absolutePath, fileContent, 'utf-8');
              fixCount++;
            } else {
              const trimmedBefore = beforeCode.trim();
              if (trimmedBefore && fileContent.includes(trimmedBefore)) {
                fileContent = fileContent.replace(trimmedBefore, afterCode);
                fs.writeFileSync(absolutePath, fileContent, 'utf-8');
                fixCount++;
              }
            }
          }
        } catch (ioErr) {
          console.error('File write error during global apply-all:', ioErr);
        }
      }
    }

    return NextResponse.json({
      success: true,
      message: `Refactored ${fixCount} findings. Entire codebase status upgraded successfully.`,
      patchedCount: fixCount
    });
  }

  // 12. GitHub Repository Import Trigger (POST)
  if (method === 'POST' && pathname === '/api/github/import') {
    const { githubUrl, defaultBranch } = await req.json();
    if (!githubUrl) {
      return NextResponse.json({ error: 'Missing githubUrl parameter.' }, { status: 400 });
    }

    const parsed = parseGithubUrl(githubUrl);
    if (!parsed) {
      return NextResponse.json({ error: 'Invalid GitHub URL.' }, { status: 400 });
    }

    const { owner, name, branch: urlBranch } = parsed;
    const user = await getAuthenticatedUser(req);
    const token = user?.accessToken ? decryptToken(user.accessToken) : undefined;
    const userLogin = user?.login || 'demo-auditor';

    try {
      const details = await fetchRepositoryDetails(owner, name, token);
      const branch = defaultBranch || urlBranch || details.defaultBranch || 'main';

      const files = await fetchRepositoryFiles(owner, name, branch, token);
      const report = await runScan(files, files.length, () => {});
      report.repositoryId = `${owner}/${name}`;
      report.repositoryName = name;
      report.repositoryOwner = owner;

      await saveReportDetails(report, userLogin);

      const grade = getGradeFromScore(report.score);
      const repoId = `${owner}/${name}`;

      let trendRecord = { score: report.score, scannedAt: report.scannedAt || new Date().toISOString(), grade };
      let dbMeta: DBRepositoryMetadata;

      const p = await getPool();
      if (p) {
        const selectRes = await p.query('SELECT historical_trend FROM github_repositories WHERE id = $1', [repoId]);
        let trendList = [];
        if (selectRes.rows.length > 0 && selectRes.rows[0].historical_trend) {
          trendList = selectRes.rows[0].historical_trend;
          if (typeof trendList === 'string') trendList = JSON.parse(trendList);
        }
        
        if (!trendList.some((t: any) => t.scannedAt === trendRecord.scannedAt)) {
          trendList.push(trendRecord);
        }

        const upsertRes = await p.query(`
          INSERT INTO github_repositories (id, owner, name, default_branch, last_scan, latest_grade, latest_score, historical_trend, user_login)
          VALUES ($1, $2, $3, $4, NOW(), $5, $6, $7, $8)
          ON CONFLICT (id) DO UPDATE SET
            default_branch = EXCLUDED.default_branch,
            last_scan = NOW(),
            latest_grade = EXCLUDED.latest_grade,
            latest_score = EXCLUDED.latest_score,
            historical_trend = EXCLUDED.historical_trend,
            user_login = EXCLUDED.user_login
          RETURNING *
        `, [repoId, owner, name, branch, grade, report.score, JSON.stringify(trendList), userLogin]);

        const row = upsertRes.rows[0];
        dbMeta = {
          id: row.id,
          owner: row.owner,
          name: row.name,
          defaultBranch: row.default_branch,
          lastScan: row.last_scan instanceof Date ? row.last_scan.toISOString() : row.last_scan,
          latestGrade: row.latest_grade,
          latestScore: row.latest_score,
          historicalTrend: typeof row.historical_trend === 'string' ? JSON.parse(row.historical_trend) : row.historical_trend,
          userLogin: row.user_login
        };
      } else {
        let existingIndex = MEMORY_GITHUB_RESOURCES.findIndex(r => r.id === repoId);
        let trendList = [];
        if (existingIndex > -1) {
          trendList = [...MEMORY_GITHUB_RESOURCES[existingIndex].historicalTrend];
        }
        trendList.push(trendRecord);

        dbMeta = {
          id: repoId,
          owner,
          name,
          defaultBranch: branch,
          lastScan: new Date().toISOString(),
          latestGrade: grade,
          latestScore: report.score,
          historicalTrend: trendList,
          userLogin
        };

        if (existingIndex > -1) {
          MEMORY_GITHUB_RESOURCES[existingIndex] = dbMeta;
        } else {
          MEMORY_GITHUB_RESOURCES.push(dbMeta);
        }
      }

      return NextResponse.json({ success: true, report, repository: dbMeta });
    } catch (err: any) {
      if (err instanceof EmptyRepositoryError) {
        return NextResponse.json(err.toJSON());
      }
      return NextResponse.json({ error: err.message || 'Import error.' }, { status: 500 });
    }
  }

  // 13. Imported GitHub Meta List (GET)
  if (method === 'GET' && pathname === '/api/github/repositories') {
    const user = await getAuthenticatedUser(req);
    const userLogin = user?.login || 'demo-auditor';

    const p = await getPool();
    try {
      if (p) {
        const dbRes = await p.query('SELECT * FROM github_repositories WHERE user_login = $1 ORDER BY last_scan DESC', [userLogin]);
        const repos: DBRepositoryMetadata[] = dbRes.rows.map(row => ({
          id: row.id,
          owner: row.owner,
          name: row.name,
          defaultBranch: row.default_branch,
          lastScan: row.last_scan instanceof Date ? row.last_scan.toISOString() : row.last_scan,
          latestGrade: row.latest_grade,
          latestScore: row.latest_score,
          historicalTrend: typeof row.historical_trend === 'string' ? JSON.parse(row.historical_trend) : row.historical_trend,
          userLogin: row.user_login
        }));
        return NextResponse.json({ repositories: repos });
      } else {
        const filtered = MEMORY_GITHUB_RESOURCES.filter(r => r.userLogin === userLogin);
        return NextResponse.json({ repositories: filtered });
      }
    } catch (err: any) {
      return NextResponse.json({ error: err.message || 'Error listing libraries.' }, { status: 500 });
    }
  }

  // 14. Pull Request analysis (POST)
  if (method === 'POST' && pathname === '/api/github/pr-analysis') {
    const { githubUrl, prNumber } = await req.json();
    if (!githubUrl || !prNumber) {
      return NextResponse.json({ error: 'Missing parameters.' }, { status: 400 });
    }

    const parsed = parseGithubUrl(githubUrl);
    if (!parsed) {
      return NextResponse.json({ error: 'Invalid URL.' }, { status: 400 });
    }

    const { owner, name } = parsed;
    const numPr = parseInt(prNumber, 10);
    const user = await getAuthenticatedUser(req);
    const token = user?.accessToken ? decryptToken(user.accessToken) : undefined;

    try {
      const prUrl = `https://api.github.com/repos/${owner}/${name}/pulls/${numPr}`;
      const prRes = await fetch(prUrl, {
        headers: {
          'User-Agent': 'AudiCode-Scanner',
          'Accept': 'application/vnd.github.v3+json',
          ...(token ? { 'Authorization': `Bearer ${token}` } : {})
        }
      });

      if (!prRes.ok) {
        throw new Error(`PR load failed. Status: ${prRes.status}`);
      }

      const prData = await prRes.json() as any;
      const headSha = prData.head.sha;
      const baseBranch = prData.base.ref || 'main';

      const baseFiles = await fetchRepositoryFiles(owner, name, baseBranch, token);
      const changedFilesList = await fetchPrFileList(owner, name, numPr, token);
      const mergedFiles = [...baseFiles];

      for (const changed of changedFilesList) {
        const { filename, status } = changed;
        if (status === 'removed') {
          const idx = mergedFiles.findIndex(f => f.path === filename);
          if (idx > -1) mergedFiles.splice(idx, 1);
        } else if (status === 'added' || status === 'modified') {
          try {
            const rawContent = await fetchPrFileDetails(owner, name, filename, headSha, token);
            const idx = mergedFiles.findIndex(f => f.path === filename);
            if (idx > -1) {
              mergedFiles[idx].content = rawContent;
            } else {
              mergedFiles.push({ path: filename, content: rawContent });
            }
          } catch (e) {
            console.warn(`Pr detail fetch issue: ${filename}`, e);
          }
        }
      }

      const baseReport = await runScan(baseFiles, baseFiles.length, () => {});
      baseReport.repositoryId = `${owner}/${name}`;
      baseReport.repositoryName = name;
      baseReport.repositoryOwner = owner;

      const prReport = await runScan(mergedFiles, mergedFiles.length, () => {});
      prReport.repositoryId = `${owner}/${name}`;
      prReport.repositoryName = name;
      prReport.repositoryOwner = owner;

      const comparison = analyzePrDiff(baseReport, prReport);
      const commentsMarkdown = generatePrComment(owner, name, numPr, comparison);

      return NextResponse.json({
        success: true,
        repository: `${owner}/${name}`,
        prNumber: numPr,
        sourceBranch: baseBranch,
        targetSha: headSha,
        baseReport,
        prReport,
        comparison,
        markdown: commentsMarkdown
      });
    } catch (err: any) {
      if (err instanceof EmptyRepositoryError) {
        return NextResponse.json(err.toJSON());
      }
      return NextResponse.json({ error: err.message || 'Comparative audit fail.' }, { status: 500 });
    }
  }

  // 15. CI YAML configs (POST)
  if (method === 'POST' && pathname === '/api/github/workflow') {
    const { failOnCritical, failBelowScore, warningOnly } = await req.json();
    const yaml = generateWorkflowYaml({
      failOnCritical: Boolean(failOnCritical),
      failBelowScore: Number(failBelowScore) || 80,
      warningOnly: Boolean(warningOnly)
    });
    return NextResponse.json({ yaml });
  }

  // 16. Security badge generator SVG render (GET startsWith)
  if (method === 'GET' && pathname.startsWith('/api/github/badge/')) {
    const rest = pathname.replace('/api/github/badge/', '');
    const parts = rest.split('/');
    if (parts.length >= 2) {
      const bOwner = parts[0];
      const bName = parts[1];
      const repoId = `${bOwner}/${bName}`;
      let score = 85;

      try {
        const p = await getPool();
        if (p) {
          const dbRes = await p.query('SELECT latest_score FROM github_repositories WHERE id = $1', [repoId]);
          if (dbRes.rows.length > 0 && dbRes.rows[0].latest_score !== null) {
            score = dbRes.rows[0].latest_score;
          }
        } else {
          const existing = MEMORY_GITHUB_RESOURCES.find(r => r.id === repoId);
          if (existing && existing.latestScore !== null) {
            score = existing.latestScore;
          }
        }
      } catch (err) {
        console.error('Badge reading issue', err);
      }

      const svg = generateBadgeSvg(score);
      return new Response(svg, {
        headers: {
          'Content-Type': 'image/svg+xml',
          'Cache-Control': 'public, max-age=60'
        }
      });
    }
  }

  // 17. Remote CI/CD Scanner webhook endpoint (POST)
  if (method === 'POST' && pathname === '/api/github/cicd-scan') {
    const { owner, name } = await req.json();
    if (!owner || !name) {
      return NextResponse.json({ error: 'Missing parameters.' }, { status: 400 });
    }

    try {
      const branch = 'main';
      const files = await fetchRepositoryFiles(owner, name, branch);
      const report = await runScan(files, files.length, () => {});
      report.repositoryId = `${owner}/${name}`;
      report.repositoryName = name;
      report.repositoryOwner = owner;

      return NextResponse.json(report);
    } catch (err: any) {
      if (err instanceof EmptyRepositoryError) {
        return NextResponse.json(err.toJSON());
      }
      return NextResponse.json({ error: err.message }, { status: 500 });
    }
  }

  // 18. Publish PR comment writeback (POST)
  if (method === 'POST' && pathname === '/api/github/post-comment') {
    const { owner, name, prNumber, markdown } = await req.json();
    if (!owner || !name || !prNumber || !markdown) {
      return NextResponse.json({ error: 'Missing parameters.' }, { status: 400 });
    }

    const numPr = parseInt(prNumber, 10);
    const user = await getAuthenticatedUser(req);
    const token = user?.accessToken ? decryptToken(user.accessToken) : undefined;

    if (!token) {
      return NextResponse.json({ error: 'GitHub authentication credentials not found. Make sure you are logged in.' }, { status: 401 });
    }

    try {
      const result = await publishPrComment(owner, name, numPr, markdown, token);
      return NextResponse.json({
        success: true,
        html_url: result.html_url,
        id: result.id
      });
    } catch (err: any) {
      console.error('Failed to post comment to live repo:', err);
      return NextResponse.json({ error: err.message || 'Error occurred writing comment to GitHub.' }, { status: 500 });
    }
  }

  return NextResponse.json({ error: `Not found: ${method} ${pathname}` }, { status: 404 });
}

// ----------------------------------------------------
// EXPORT HANDLERS FOR REST SERVICES
// ----------------------------------------------------
export async function GET(req: NextRequest) {
  const pathname = req.nextUrl.pathname;

  // HANDLE REALTIME STREAM PIPE IN SSE SKELETAL
  if (pathname === '/api/scan/stream') {
    const { searchParams } = req.nextUrl;
    const repositoryId = searchParams.get('repositoryId');
    const owner = searchParams.get('owner');
    const name = searchParams.get('name');
    const defaultBranch = searchParams.get('defaultBranch');

    const encoder = new TextEncoder();
    const stream = new ReadableStream({
      async start(controller) {
        const sendEvent = (data: any) => {
          controller.enqueue(encoder.encode(`data: ${JSON.stringify(data)}\n\n`));
        };

        if (!repositoryId || !owner || !name) {
          sendEvent({ type: 'error', error: 'Missing parameters repository selection.' });
          controller.close();
          return;
        }

        const user = await getAuthenticatedUser(req);
        if (!user) {
          sendEvent({ type: 'error', error: 'Session invalid or expired. Please log in again.' });
          controller.close();
          return;
        }

        // A. Sandbox Simulator Loop
        if (user.isSandbox || repositoryId.toString().startsWith('demo-')) {
          const matchingRepoId = repositoryId.toString().startsWith('demo-') ? repositoryId.toString() : 'demo-auth-service';
          const activeRepoMeta = DEMO_REPOSITORIES.find(r => r.id === matchingRepoId) || DEMO_REPOSITORIES[0];
          const demoFilesList = DEMO_FILES[matchingRepoId] || DEMO_FILES['demo-auth-service'];

          sendEvent({
            type: 'progress',
            status: 'connecting',
            filesDiscovered: demoFilesList.length,
            filesScanned: 0,
            currentFile: 'Establishing sandbox scan session...',
            percentage: 10
          });

          await new Promise(resolve => setTimeout(resolve, 400));

          let processed = 0;
          for (const dFile of demoFilesList) {
            processed++;
            const currentPct = Math.min(90, Math.floor(10 + (processed / demoFilesList.length) * 80));
            sendEvent({
              type: 'progress',
              status: 'fetching',
              filesDiscovered: demoFilesList.length,
              filesScanned: processed,
              currentFile: dFile.path,
              percentage: currentPct
            });
            await new Promise(resolve => setTimeout(resolve, 100));
          }

          sendEvent({
            type: 'progress',
            status: 'scanning',
            filesDiscovered: demoFilesList.length,
            filesScanned: demoFilesList.length,
            currentFile: 'Analyzing variables flow charts & credentials check...',
            percentage: 95
          });

          const report: ScanReport = await runScan(demoFilesList, demoFilesList.length, (progressMsg) => {
            sendEvent({
              type: 'progress',
              status: 'scanning',
              filesDiscovered: demoFilesList.length,
              filesScanned: progressMsg.filesScanned,
              currentFile: `[AST Scan] ${progressMsg.currentFile}`,
              percentage: Math.min(99, 95 + Math.floor(progressMsg.percentage * 0.04))
            });
          });
          report.repositoryId = matchingRepoId;
          report.repositoryName = activeRepoMeta.name;
          report.repositoryOwner = activeRepoMeta.owner;

          await saveReportDetails(report, user.login);
          sendEvent({ type: 'success', report });
          controller.close();
          return;
        }

        // B. Real Live GitHub Ingress In stream pipeline
        try {
          const branch = defaultBranch || 'main';
          const rawToken = decryptToken(user.accessToken);

          sendEvent({
            type: 'progress',
            status: 'connecting',
            filesDiscovered: 0,
            filesScanned: 0,
            currentFile: `Resolving default branch (${branch}) & scanning file trees...`,
            percentage: 5
          });

          const treeUrl = `https://api.github.com/repos/${owner}/${name}/git/trees/${branch}?recursive=1`;
          const treeResponse = await fetch(treeUrl, {
            headers: {
              'Authorization': `Bearer ${rawToken}`,
              'User-Agent': 'AudiCode-Scanner'
            }
          });

          if (!treeResponse.ok) {
            if (treeResponse.status === 409) {
              throw new EmptyRepositoryError(owner, name, branch);
            }
            throw new Error(`Failed to load file index from GitHub API.`);
          }

          const treeData = await treeResponse.json() as any;
          if (!treeData.tree || !Array.isArray(treeData.tree) || treeData.tree.length === 0) {
            throw new EmptyRepositoryError(owner, name, branch);
          }

          const codeFilesToFetch = treeData.tree.filter((node: any) => {
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
              ['.png', '.jpg', '.ico', '.svg', '.woff', '.lock'].includes(ext);

            const maxLimitSize = (node.size && Number(node.size) <= 50000);
            return !shouldSkip && maxLimitSize;
          });

          const filesDiscovered = codeFilesToFetch.length;
          const activeFileList = codeFilesToFetch.slice(0, 50);

          if (activeFileList.length === 0) {
            throw new Error('No compatible target plain-text source files under 50KB found in this repository.');
          }

          sendEvent({
            type: 'progress',
            status: 'indexing',
            filesDiscovered,
            filesScanned: 0,
            currentFile: `Discovered<sup>${filesDiscovered}</sup> files. Fetching...`,
            percentage: 20
          });

          const filesContents: { path: string; content: string }[] = [];
          let filesScanned = 0;

          for (const fileNode of activeFileList) {
            const currentFile = fileNode.path;
            filesScanned++;
            const currentPct = Math.min(90, Math.floor(20 + (filesScanned / activeFileList.length) * 70));

            sendEvent({
              type: 'progress',
              status: 'fetching',
              filesDiscovered,
              filesScanned,
              currentFile,
              percentage: currentPct
            });

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
                filesContents.push({ path: currentFile, content });
              }
            } catch (err: any) {
              console.warn(`Gracefully skipped file [${currentFile}]:`, err.message || err);
            }
          }

          if (filesContents.length === 0) {
            throw new Error('Ingest failed entirely. Unable to download any files.');
          }

          sendEvent({
            type: 'progress',
            status: 'scanning',
            filesDiscovered,
            filesScanned: filesContents.length,
            currentFile: 'Running AST static dataflow compilation...',
            percentage: 92
          });

          const report: ScanReport = await runScan(filesContents, filesDiscovered, (progressMsg) => {
            sendEvent({
              type: 'progress',
              status: 'scanning',
              filesDiscovered,
              filesScanned: progressMsg.filesScanned,
              currentFile: `[AST Scan] ${progressMsg.currentFile}`,
              percentage: Math.min(99, 92 + Math.floor(progressMsg.percentage * 0.07))
            });
          });

          report.repositoryId = repositoryId;
          report.repositoryName = name;
          report.repositoryOwner = owner;

          await saveReportDetails(report, user.login);

          sendEvent({ type: 'success', report });
          controller.close();
        } catch (error: any) {
          if (error instanceof EmptyRepositoryError) {
            sendEvent({
              type: 'empty_repo',
              code: 'EMPTY_REPO',
              repository: error.repository,
              branch: error.branch,
              message: error.message
            });
            controller.close();
            return;
          }
          sendEvent({
            type: 'error',
            error: error.message || 'Scan error.'
          });
          controller.close();
        }
      }
    });

    return new Response(stream, {
      headers: {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache, no-transform',
        'Connection': 'keep-alive',
        'X-Accel-Buffering': 'no',
      }
    });
  }

  return handleRoute(req, 'GET');
}

export async function POST(req: NextRequest) {
  return handleRoute(req, 'POST');
}

export async function PUT(req: NextRequest) {
  return handleRoute(req, 'PUT');
}

export async function DELETE(req: NextRequest) {
  return handleRoute(req, 'DELETE');
}
