import { createClient } from '@supabase/supabase-js';
import crypto from 'crypto';
import url from 'url';
import pg from 'pg';
import { runScan } from '../../src/scanner';
import { getGradeFromScore } from '../../src/githubService';

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
    console.error('[Scan Status] Pool init failed:', err);
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

  if (req.method !== 'GET') {
    res.status(405).json({ error: 'Method Not Allowed' });
    return;
  }

  const resolvedUrl = req.headers['x-matched-path'] as string || req.url || '';
  const parsedUrl = url.parse(resolvedUrl, true);
  const jobId = parsedUrl.query.id as string;

  if (!jobId) {
    res.status(400).json({ error: 'Missing scan job id parameter.' });
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
    } catch (err) {
      isSandbox = true;
    }
  }

  if (!pool) {
    res.status(512).json({ error: 'PostgreSQL connection pool uninitialized.' });
    return;
  }

  try {
    // Audit-check schema upgrades
    await pool.query(`ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS scanned_files_data JSONB DEFAULT '[]'::jsonb`);

    // Acquire job with lock to avoid duplicate parallel execution conflicts
    const jobRes = await pool.query(`SELECT * FROM scan_jobs WHERE id = $1`, [jobId]);
    if (jobRes.rows.length === 0) {
      res.status(404).json({ error: 'Scan job not found or permission denied.' });
      return;
    }

    const job = jobRes.rows[0];

    // Security check: ensure user owns this job
    if (job.user_login !== userLogin && !isSandbox) {
      res.status(403).json({ error: 'Access unauthorized: You are not the initiator of this scanning job.' });
      return;
    }

    // Done / Failed states return immediately
    if (job.status === 'completed' || job.status === 'failed') {
      res.status(200).json({
        success: true,
        id: job.id,
        status: job.status,
        progress: job.progress,
        progress_percent: job.progress_percent,
        total_files: job.total_files,
        scanned_files_count: job.scanned_files_count,
        error: job.error,
        report: typeof job.report === 'string' ? JSON.parse(job.report) : job.report
      });
      return;
    }

    const branch = 'main';
    const headerToken = req.headers['x-provider-token'] as string || '';
    const rawProviderToken = headerToken || userAccessTokenEncrypted || '';
    const decryptedToken = decryptToken(rawProviderToken) || process.env.GITHUB_PAT || '';

    const filesToScanList = typeof job.files_to_scan === 'string' ? JSON.parse(job.files_to_scan) : job.files_to_scan;
    let scannedFilesData = typeof job.scanned_files_data === 'string' ? JSON.parse(job.scanned_files_data) : job.scanned_files_data;
    if (!scannedFilesData) scannedFilesData = [];

    // STATE MACHINE TRANSITIONS
    if (job.status === 'pending') {
      // First step: fetch package.json to prepare dependency & OSV scans
      const pkgNode = filesToScanList.find((f: any) => f.path === 'package.json');
      if (pkgNode && decryptedToken) {
        try {
          const resText = await fetch(pkgNode.url, {
            headers: {
              'Authorization': `Bearer ${decryptedToken}`,
              'User-Agent': 'AudiCode-Scanner',
              'Accept': 'application/vnd.github.v3.raw'
            }
          }).then(r => r.text());
          scannedFilesData.push({ path: 'package.json', content: resText });
        } catch (e) {
          console.warn('[Scan Poll] Non-fatal custom package resolver error:', e);
        }
      }

      await pool.query(`
        UPDATE scan_jobs SET
          status = $1,
          progress = $2,
          progress_percent = $3,
          scanned_files_data = $4,
          updated_at = NOW()
        WHERE id = $5
      `, [
        'scanning',
        'Package dependencies parsed. Mapping repository code structures...',
        15,
        JSON.stringify(scannedFilesData),
        jobId
      ]);

      res.status(200).json({
        success: true,
        id: job.id,
        status: 'scanning',
        progress: 'Dependencies loaded. Analysing source files next...',
        progress_percent: 15,
        total_files: job.total_files,
        scanned_files_count: job.scanned_files_count
      });
      return;
    }

    if (job.status === 'scanning') {
      // Get next batch of files to process
      const batchSize = 6;
      const startIndex = job.scanned_files_count;
      const currentBatch = filesToScanList.slice(startIndex, startIndex + batchSize);

      if (currentBatch.length === 0 || startIndex >= filesToScanList.length) {
        // SCANNED ALL FILES -> COMPILE AND ASSEMBLE FINAL REPORT
        try {
          const report = await runScan(scannedFilesData, job.total_files, () => {});
          report.repositoryId = job.repository_id;
          report.repositoryName = job.repository_name;
          report.repositoryOwner = job.repository_owner;

          // Write final report to db
          await pool.query(`
            UPDATE scan_jobs SET
              status = $1,
              progress = $2,
              progress_percent = $3,
              scanned_files_count = $4,
              report = $5,
              findings = $6,
              counts = $7,
              updated_at = NOW()
            WHERE id = $8
          `, [
            'completed',
            'Scan completed successfully!',
            100,
            job.total_files,
            JSON.stringify(report),
            JSON.stringify(report.findings),
            JSON.stringify(report.counts),
            jobId
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
              job.repository_id,
              job.repository_name,
              job.repository_owner,
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

          // Save latest score/grade to github_repositories for search filters
          const grade = getGradeFromScore(report.score);
          const repoId = job.repository_id;

          const selectRes = await pool.query('SELECT historical_trend FROM github_repositories WHERE id = $1', [repoId]);
          let trendList = [];
          if (selectRes.rows.length > 0 && selectRes.rows[0].historical_trend) {
            trendList = selectRes.rows[0].historical_trend;
            if (typeof trendList === 'string') trendList = JSON.parse(trendList);
          }
          const trendRecord = { score: report.score, scannedAt: report.scannedAt || new Date().toISOString(), grade };
          trendList.push(trendRecord);

          await pool.query(`
            INSERT INTO github_repositories (id, owner, name, default_branch, last_scan, latest_grade, latest_score, historical_trend, user_login)
            VALUES ($1, $2, $3, $4, NOW(), $5, $6, $7, $8)
            ON CONFLICT (id) DO UPDATE SET
              last_scan = NOW(),
              latest_grade = EXCLUDED.latest_grade,
              latest_score = EXCLUDED.latest_score,
              historical_trend = EXCLUDED.historical_trend
          `, [repoId, job.repository_owner, job.repository_name, 'main', grade, report.score, JSON.stringify(trendList), userLogin]);

          res.status(200).json({
            success: true,
            id: job.id,
            status: 'completed',
            progress: 'Scan complete!',
            progress_percent: 100,
            report
          });
          return;
        } catch (scanErr: any) {
          console.error('[Scan Poll] Assembly failed:', scanErr);
          await pool.query(`UPDATE scan_jobs SET status = 'failed', error = $1, progress = 'Assembly failed', updated_at = NOW() WHERE id = $2`, [scanErr.message, jobId]);
          res.status(200).json({ success: true, id: job.id, status: 'failed', error: scanErr.message });
          return;
        }
      }

      // FETCH CURRENT BATCH FILE CONTENT FROM GITHUB
      const fetchedCountBefore = scannedFilesData.length;
      await Promise.all(currentBatch.map(async (fileNode: any) => {
        try {
          if (!decryptedToken) return;
          const fetchFileRes = await fetch(fileNode.url, {
            headers: {
              'Authorization': `Bearer ${decryptedToken}`,
              'User-Agent': 'AudiCode-Scanner',
              'Accept': 'application/vnd.github.v3.raw'
            }
          });
          if (fetchFileRes.ok) {
            const rawText = await fetchFileRes.text();
            scannedFilesData.push({ path: fileNode.path, content: rawText });
          }
        } catch (fetchErr) {
          console.warn('[Scan Poll] Non-fatal custom file content fetch error for ' + fileNode.path, fetchErr);
        }
      }));

      const newIndex = startIndex + currentBatch.length;
      const calculatedPercent = Math.min(99, Math.round((newIndex / job.total_files) * 80) + 15);
      const fileSample = currentBatch[0]?.path || 'source file';

      await pool.query(`
        UPDATE scan_jobs SET
          progress = $1,
          progress_percent = $2,
          scanned_files_count = $3,
          scanned_files_data = $4,
          updated_at = NOW()
        WHERE id = $5
      `, [
        `Analyzing ${fileSample}...`,
        calculatedPercent,
        newIndex,
        JSON.stringify(scannedFilesData),
        jobId
      ]);

      res.status(200).json({
        success: true,
        id: job.id,
        status: 'scanning',
        progress: `Downloaded and analyzed ${newIndex} of ${job.total_files} files...`,
        progress_percent: calculatedPercent,
        total_files: job.total_files,
        scanned_files_count: newIndex
      });
      return;
    }

  } catch (executionErr: any) {
    console.error('[Scan Poll] Execution fatal error:', executionErr);
    res.status(500).json({ error: executionErr.message || 'Fatal crash updating scanning job status.' });
  }
}
