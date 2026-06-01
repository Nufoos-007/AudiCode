import { createClient } from '@supabase/supabase-js';
import crypto from 'crypto';
import url from 'url';
import pg from 'pg';
import { runScan } from '../../src/scanner';
import { DEMO_REPOSITORIES, DEMO_FILES } from './demo';

const { Pool } = pg;

const supabaseUrl = process.env.SUPABASE_URL || process.env.VITE_SUPABASE_URL || '';
const supabaseAnonKey = process.env.SUPABASE_ANON_KEY || process.env.VITE_SUPABASE_ANON_KEY || '';
const supabase = (supabaseUrl && supabaseAnonKey)
  ? createClient(supabaseUrl, supabaseAnonKey)
  : null;

const databaseUrl = process.env.DATABASE_URL;
let pool: pg.Pool | null = null;
if (databaseUrl) {
  try {
    pool = new Pool({
      connectionString: databaseUrl,
      ssl: databaseUrl.includes('supabase') || databaseUrl.includes('render') || databaseUrl.includes('elephantsql') || databaseUrl.includes('localhost') === false
        ? { rejectUnauthorized: false }
        : undefined
    });
  } catch (err) {
    console.error('[Scan Start] Pool init failed:', err);
  }
}

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
    console.error('[Token Audit] Cryptographic decryption failed:', err);
    return encryptedToken;
  }
}

function parseCookies(cookieStr: string | undefined): Record<string, string> {
  const cookies: Record<string, string> = {};
  if (!cookieStr) return cookies;
  cookieStr.split(';').forEach(pair => {
    const parts = pair.split('=');
    const name = parts[0].trim();
    const val = parts[1] ? parts[1].trim() : '';
    cookies[name] = decodeURIComponent(val);
  });
  return cookies;
}

function enhanceResponse(res: any) {
  if (!res.status) {
    res.status = (code: number) => {
      res.statusCode = code;
      return res;
    };
  }
  if (!res.json) {
    res.json = (data: any) => {
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify(data));
      return res;
    };
  }
}

export default async function handler(req: any, res: any) {
  enhanceResponse(res);

  if (req.method !== 'POST') {
    res.status(405).json({ error: 'Method Not Allowed' });
    return;
  }

  // Parse authorization & headers
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.substring(7) : '';

  const cookies = parseCookies(req.headers.cookie);
  const activeSbToken = token || cookies.audi_token || '';

  let userLogin = 'demo-auditor';
  let isSandbox = activeSbToken === 'demo_token_sandbox_bypass_true' || cookies.audi_sandbox === 'true';
  let userAccessTokenEncrypted = '';

  if (!isSandbox) {
    if (!activeSbToken) {
      res.status(401).json({ error: 'Session token invalid or expired. Please login again.' });
      return;
    }

    if (!supabase) {
      res.status(500).json({ error: 'Supabase integration is not fully configured.' });
      return;
    }

    try {
      const { data: { user }, error: authError } = await supabase.auth.getUser(activeSbToken);
      if (authError || !user) {
        res.status(401).json({ error: 'Authentication failed: Invalid token.' });
        return;
      }
      userLogin = user.user_metadata?.user_name || user.email || 'github-user';
      userAccessTokenEncrypted = user.user_metadata?.provider_token || '';
    } catch (err: any) {
      console.error('[Scan Start] Authentication error:', err);
      // fallback to sandbox if any issue
      isSandbox = true;
    }
  }

  // Parse body
  let body: any = {};
  if (req.body) {
    body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
  } else {
    // Wait for body parser stream in Vite server context
    try {
      const buffers: any[] = [];
      for await (const chunk of req) {
        buffers.push(chunk);
      }
      const rawBody = Buffer.concat(buffers).toString();
      body = rawBody ? JSON.parse(rawBody) : {};
    } catch (e) {
      body = {};
    }
  }

  const { repositoryId, owner, name, defaultBranch } = body;

  if (!repositoryId || !owner || !name) {
    res.status(400).json({ error: 'Missing parameters. Please select a repository.' });
    return;
  }

  const jobId = 'sj_' + crypto.randomBytes(12).toString('hex');

  // Verify/create PostgreSQL job tables
  if (pool) {
    try {
      await pool.query(`
        CREATE TABLE IF NOT EXISTS scan_jobs (
          id TEXT PRIMARY KEY,
          repository_id TEXT NOT NULL,
          repository_name TEXT NOT NULL,
          repository_owner TEXT NOT NULL,
          status TEXT NOT NULL,
          progress TEXT NOT NULL,
          progress_percent INTEGER DEFAULT 0,
          error TEXT,
          total_files INTEGER DEFAULT 0,
          scanned_files_count INTEGER DEFAULT 0,
          files_to_scan JSONB DEFAULT '[]'::jsonb,
          findings JSONB DEFAULT '[]'::jsonb,
          counts JSONB DEFAULT '{"critical": 0, "high": 0, "medium": 0, "low": 0}'::jsonb,
          user_login TEXT NOT NULL,
          report JSONB,
          created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
          updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );
      `);
    } catch (tblErr: any) {
      console.error('[Scan Start] Schema creation error:', tblErr);
    }
  }

  // Handle Demo / Sandbox repositories immediately using local runScan (completes offline under 100ms)
  if (isSandbox || repositoryId.toString().startsWith('demo-')) {
    try {
      const matchingRepoId = repositoryId.toString().startsWith('demo-') ? repositoryId.toString() : 'demo-auth-service';
      const files = DEMO_FILES[matchingRepoId] || DEMO_FILES['demo-auth-service'];
      const activeRepoMeta = DEMO_REPOSITORIES.find(r => r.id === matchingRepoId) || DEMO_REPOSITORIES[0];

      // Run scan synchronously in 10ms
      const report = await runScan(files, files.length, () => {});
      report.repositoryId = matchingRepoId;
      report.repositoryName = activeRepoMeta.name;
      report.repositoryOwner = activeRepoMeta.owner;

      if (pool) {
        await pool.query(`
          INSERT INTO scan_jobs (
            id, repository_id, repository_name, repository_owner, status, progress, progress_percent,
            total_files, scanned_files_count, findings, counts, user_login, report
          ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
        `, [
          jobId,
          matchingRepoId,
          activeRepoMeta.name,
          activeRepoMeta.owner,
          'completed',
          'Sandbox Scan Completed!',
          100,
          files.length,
          files.length,
          JSON.stringify(report.findings),
          JSON.stringify(report.counts),
          userLogin,
          JSON.stringify(report)
        ]);

        // Save report details so they appear in history list
        await pool.query(`
          INSERT INTO scan_reports (
            id, repository_id, repository_name, repository_owner, scanned_at, time_elapsed_ms,
            total_files_scanned, score, counts, findings, user_login,
            frameworks_detected, ai_generated_probability, ai_risk_level, ai_architecture_quality, ai_factors_text
          ) VALUES ($1, $2, $3, $4, NOW(), $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
          ON CONFLICT (id) DO UPDATE SET
            scanned_at = NOW(),
            time_elapsed_ms = EXCLUDED.time_elapsed_ms,
            total_files_scanned = EXCLUDED.total_files_scanned,
            score = EXCLUDED.score,
            counts = EXCLUDED.counts,
            findings = EXCLUDED.findings
          `, [
            report.id,
            matchingRepoId,
            activeRepoMeta.name,
            activeRepoMeta.owner,
            report.timeElapsedMs,
            report.totalFilesScanned,
            report.score,
            JSON.stringify(report.counts),
            JSON.stringify(report.findings),
            userLogin,
            JSON.stringify(report.frameworksDetected || []),
            report.aiGeneratedProbability || 15,
            report.aiRiskLevel || 'LOW',
            report.aiArchitectureQuality || 'EXCELLENT',
            JSON.stringify(report.aiFactorsText || [])
          ]);
      }

      res.status(200).json({ success: true, scanId: jobId });
      return;
    } catch (demoErr: any) {
      console.error('[Scan Start] Demo initialization failure:', demoErr);
      res.status(500).json({ error: 'Sandbox scan execution failed: ' + demoErr.message });
      return;
    }
  }

  // Handle Real GitHub Repo: Fetch file tree recursively to assemble job
  try {
    const branch = defaultBranch || 'main';
    const headerToken = req.headers['x-provider-token'] as string || '';
    const rawProviderToken = headerToken || userAccessTokenEncrypted || '';
    const decryptedToken = decryptToken(rawProviderToken) || process.env.GITHUB_PAT || '';

    if (!decryptedToken) {
      res.status(400).json({ error: 'GitHub access token is missing or expired. Please log out and authentication source again.' });
      return;
    }

    const treeUrl = `https://api.github.com/repos/${owner}/${name}/git/trees/${branch}?recursive=1`;
    const treeResponse = await fetch(treeUrl, {
      headers: {
        'Authorization': `Bearer ${decryptedToken}`,
        'User-Agent': 'AudiCode-Scanner'
      }
    });

    if (!treeResponse.ok) {
      if (treeResponse.status === 409) {
        res.status(200).json({
          type: 'empty_repo',
          code: 'EMPTY_REPO',
          repository: `${owner}/${name}`,
          branch,
          message: 'Repository is empty.'
        });
        return;
      }
      throw new Error(`Failed to read repository assets (Is default branch correct?)`);
    }

    const treeData = await treeResponse.json() as any;
    if (!treeData.tree || !Array.isArray(treeData.tree) || treeData.tree.length === 0) {
      res.status(200).json({
        type: 'empty_repo',
        code: 'EMPTY_REPO',
        repository: `${owner}/${name}`,
        branch,
        message: 'Repository has no tree assets.'
      });
      return;
    }

    // Filter relevant code files (< 50KB, relevant extension, skip binaries and build configs)
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
        p.includes('mock/') ||
        p.includes('mocks/') ||
        ext === '.png' ||
        ext === '.jpg' ||
        ext === '.ico' ||
        ext === '.svg' ||
        ext === '.woff' ||
        ext === '.woff2' ||
        ext === '.pdf' ||
        ext === '.lock';
      const isConfigOnly = p.includes('.config.') || p === 'package-lock.json';
      const sizeLimit = (node.size && Number(node.size) <= 50000);
      return !shouldSkip && sizeLimit && !isConfigOnly;
    }).map((node: any) => ({
      path: node.path,
      url: node.url,
      size: node.size
    }));

    // Target up to 45 key files for robust performance and security validation
    const filesToScan = codeFilesToFetch.slice(0, 45);

    if (filesToScan.length === 0) {
      throw new Error('No compatible text source files under 50KB found in this repository.');
    }

    if (pool) {
      await pool.query(`
        INSERT INTO scan_jobs (
          id, repository_id, repository_name, repository_owner, status, progress, progress_percent,
          total_files, scanned_files_count, files_to_scan, findings, user_login
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
      `, [
        jobId,
        repositoryId,
        name,
        owner,
        'pending',
        'Repository verified. Resolving package dependencies and OSV live advisories next...',
        5,
        filesToScan.length,
        0,
        JSON.stringify(filesToScan),
        JSON.stringify([]),
        userLogin
      ]);
    }

    res.status(200).json({ success: true, scanId: jobId });
  } catch (err: any) {
    console.error('[Scan Start] Initialization fatal error:', err);
    res.status(500).json({ error: err.message || 'Critical pipeline exception registering scanning job.' });
  }
}
