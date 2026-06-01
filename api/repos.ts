import { createClient } from '@supabase/supabase-js';
import crypto from 'crypto';
import url from 'url';

const supabaseUrl = process.env.SUPABASE_URL || process.env.VITE_SUPABASE_URL || '';
const supabaseAnonKey = process.env.SUPABASE_ANON_KEY || process.env.VITE_SUPABASE_ANON_KEY || '';
const supabase = (supabaseUrl && supabaseAnonKey)
  ? createClient(supabaseUrl, supabaseAnonKey)
  : null;

const TOKEN_ENCRYPTION_KEY = process.env.TOKEN_ENCRYPTION_KEY || '8e5e89d1b6cfbc829da8c973551db7f7fef405c6d3df393df8a9a8f27cfde2a5';
const IV_LENGTH = 16;

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
    console.error('[Token Audit] Cryptographic decryption failed for encrypted session tokens:', err);
    return encryptedToken;
  }
}

const DEMO_REPOSITORIES = [
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
  if (!res.send) {
    res.send = (data: any) => {
      res.end(data);
      return res;
    };
  }
}

export default async function handler(req: any, res: any) {
  enhanceResponse(res);

  if (req.method !== 'GET') {
    res.status(405).json({
      success: false,
      repositories: [],
      error: 'Method Not Allowed',
      githubStatus: null,
      githubBody: null
    });
    return;
  }

  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.substring(7) : '';

  const resolvedUrl = req.headers['x-matched-path'] as string || req.url || '';
  const parsedUrl = url.parse(resolvedUrl, true);
  const querySbAccessToken = parsedUrl.query.sb_access_token as string;
  const querySbProviderToken = parsedUrl.query.sb_provider_token as string;

  const cookies = parseCookies(req.headers.cookie);
  const activeSbToken = token || querySbAccessToken;

  // Sandbox bypass or active offline cookies
  if (activeSbToken === 'demo_token_sandbox_bypass_true' || cookies.audi_sandbox === 'true') {
    res.status(200).json({
      success: true,
      repositories: DEMO_REPOSITORIES,
      error: null,
      githubStatus: null,
      githubBody: null
    });
    return;
  }

  if (!activeSbToken) {
    res.status(401).json({
      success: false,
      repositories: [],
      error: 'Active connection token is missing. Please sign in.',
      githubStatus: null,
      githubBody: null
    });
    return;
  }

  if (!supabase) {
    res.status(500).json({
      success: false,
      repositories: [],
      error: 'Supabase server-side connection client is not configured on Vercel.',
      githubStatus: null,
      githubBody: null
    });
    return;
  }

  try {
    const { data: { user }, error: authError } = await supabase.auth.getUser(activeSbToken);
    if (authError || !user) {
      res.status(401).json({
        success: false,
        repositories: [],
        error: `Invalid session token: ${authError?.message || 'Authentication failed'}`,
        githubStatus: null,
        githubBody: null
      });
      return;
    }

    const headerToken = req.headers['x-provider-token'] as string || '';
    const rawProviderToken = headerToken || querySbProviderToken || '';
    const resolvedToken = decryptToken(rawProviderToken);

    if (!resolvedToken) {
      res.status(400).json({
        success: false,
        repositories: [],
        error: 'GitHub OAuth token is missing from your active session. Please sign in again.',
        githubStatus: null,
        githubBody: null
      });
      return;
    }

    const targetUrl = 'https://api.github.com/user/repos?per_page=100&sort=pushed';
    const reposResponse = await fetch(targetUrl, {
      headers: {
        'Authorization': `Bearer ${resolvedToken}`,
        'User-Agent': 'AudiCode-Scanner'
      }
    });

    const responseText = await reposResponse.text();

    if (!reposResponse.ok) {
      res.status(reposResponse.status).json({
        success: false,
        repositories: [],
        error: `GitHub API returned error status ${reposResponse.status}`,
        githubStatus: reposResponse.status,
        githubBody: responseText.slice(0, 300)
      });
      return;
    }

    let parsed: any;
    try {
      parsed = JSON.parse(responseText);
    } catch (parseErr) {
      res.status(500).json({
        success: false,
        repositories: [],
        error: 'Failed to parse JSON response from GitHub API.',
        githubStatus: reposResponse.status,
        githubBody: responseText.slice(0, 300)
      });
      return;
    }

    if (!Array.isArray(parsed)) {
      res.status(500).json({
        success: false,
        repositories: [],
        error: 'GitHub API response did not return an array of repositories.',
        githubStatus: reposResponse.status,
        githubBody: responseText.slice(0, 300)
      });
      return;
    }

    const repositories = parsed.map((r: any) => {
      try {
        return {
          id: String(r?.id || ''),
          name: r?.name || '',
          owner: r?.owner?.login || '',
          description: r?.description || '',
          isPrivate: !!r?.private,
          defaultBranch: r?.default_branch || 'main',
          url: r?.html_url || ''
        };
      } catch {
        return null;
      }
    }).filter((r: any) => r !== null);

    res.status(200).json({
      success: true,
      repositories,
      error: null,
      githubStatus: 200,
      githubBody: null
    });

  } catch (err: any) {
    res.status(500).json({
      success: false,
      repositories: [],
      error: err.message || 'An unexpected error occurred during user repository retrieval.',
      githubStatus: null,
      githubBody: null
    });
  }
}
