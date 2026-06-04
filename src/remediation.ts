import { VulnerabilityInstance, SeverityType } from './types';

export interface RemediationTemplate {
  whyItMatters: string;
  attackScenario: string;
  recommendedFix: string;
  codeExample: string;
  estimatedTime: '5 min' | '15 min' | '30 min' | '1 hour+' | 'Architectural Change';
}

const REMEDIATION_CATALOG: Record<string, RemediationTemplate> = {
  // 1. Missing Row-Level Security
  'SUPABASE-MISSING-RLS': {
    whyItMatters: 'Row-Level Security (RLS) is Postgres\'s primary defense-in-depth boundary. When database tables lack active RLS declarations, any client possessing the public anonymous API key can bypass route restrictions to insert, view, or delete database rows directly.',
    attackScenario: 'An attacker extracts the public anonymous token from a compiled JS bundle. They use a standard REST tool to target `https://<project-id>.supabase.co/rest/v1/notes` and successfully extract every stored workspace document without authentication.',
    recommendedFix: 'Expose SQL commands to manually enable Row-Level Security on the affected tables, and define a restrictive matching user policy (e.g., matching the owner column to the request session uid).',
    estimatedTime: '15 min',
    codeExample: `-- Enable Row-Level Security explicitly on the target table\nALTER TABLE notes ENABLE ROW LEVEL SECURITY;\n\n-- Direct restricting policy allowing CRUD operations only on own records\nCREATE POLICY "Users can fully manage their own notes" \n  ON notes \n  FOR ALL \n  TO authenticated \n  USING (auth.uid() = user_id) \n  WITH CHECK (auth.uid() = user_id);`
  },

  // 2. Open Firestore Rules
  'FIREBASE-OPEN-RULES': {
    whyItMatters: 'Firebase Firestore databases are directly governed by rules files. Wide-open rules allow any arbitrary internet client running `firebase-js-sdk` to alter schema, retrieve entire document trees, or completely delete the backend store.',
    attackScenario: 'A script scans matching project metadata configurations, discovers an open rule setup (`allow read, write: if true`), and issues connection commands to wipe out users and billing logs catalog databases.',
    recommendedFix: 'Alter `firestore.rules` to demand active user authentication checking and limit collection paths to the authentic user document ownership structures.',
    estimatedTime: '15 min',
    codeExample: `rules_version = '2';\nservice cloud.firestore {\n  match /databases/{database}/documents {\n    // Protect user documents specifically containing an matching userId field\n    match /users/{userId} {\n      allow read, write: if request.auth != null && request.auth.uid == userId;\n    }\n    \n    // Secure nested collections to demand active verification\n    match /notes/{noteId} {\n      allow read, write: if request.auth != null && request.auth.uid == resource.data.userId;\n    }\n  }\n}`
  },

  // 3. Missing Auth Middleware on routes
  'AUTH-MISSING': {
    whyItMatters: 'Exposing backend controller endpoints without protective identity-verification middleware allows unauthenticated clients to issue server commands, harvest database profiles, or alter states.',
    attackScenario: 'A scraper discovers the endpoint `/api/reports/all` is unprotected. It issues a fast loop of curls, pulling out confidential customer invoice files in CSV format.',
    recommendedFix: 'Bind a centralized JSON Web Token (JWT) verification middleware directly over endpoint routes before handling business controller logic.',
    estimatedTime: '15 min',
    codeExample: `// Express.js Route Guard Middleware\nimport jwt from 'jsonwebtoken';\n\nexport const requireAuth = (req, res, next) => {\n  const token = req.headers.authorization?.split(' ')[1];\n  if (!token) {\n    return res.status(401).json({ error: 'OAuth authorization token required' });\n  }\n  \n  try {\n    const decoded = jwt.verify(token, process.env.JWT_SECRET!, {\n      algorithms: ['HS256']\n    });\n    req.user = decoded;\n    next();\n  } catch (error) {\n    return res.status(403).json({ error: 'Invalid or expired signature' });\n  }\n};\n\n// Usage on routes:\n// app.get('/api/reports/all', requireAuth, getReportsController);`
  },

  'ROUTE-UNPROTECTED': {
    whyItMatters: 'Exposing routes without explicit verification logic bypasses authentication gates entirely, enabling unauthenticated access to corporate workflows.',
    attackScenario: 'An attacker scans standard resource endpoints such as `/api/admin/metrics` and extracts system resource variables from unprotected server layouts.',
    recommendedFix: 'Implement a structured Next.js match middleware or Express chain guard to process session status.',
    estimatedTime: '15 min',
    codeExample: `// Next.js Global Middleware Example\nimport { NextResponse } from 'next/server';\nimport type { NextRequest } from 'next/server';\nimport { jwtVerify } from 'jose';\n\nexport async function middleware(request: NextRequest) {\n  const authHeader = request.headers.get('authorization');\n  const token = authHeader?.startsWith('Bearer ') ? authHeader.split(' ')[1] : null;\n\n  if (!token) {\n    return NextResponse.json({ error: 'Authentication required' }, { status: 401 });\n  }\n\n  try {\n    const secret = new TextEncoder().encode(process.env.JWT_SECRET);\n    await jwtVerify(token, secret);\n    return NextResponse.next();\n  } catch (err) {\n    return NextResponse.json({ error: 'Signature validation failed' }, { status: 403 });\n  }\n}\n\nexport const config = {\n  matcher: ['/api/admin/:path*', '/api/dashboard/:path*']\n};`
  },

  // 4. Insecure Access-Control Wildcard (CORS Open)
  'WEB-CORS-OPEN': {
    whyItMatters: 'Wildcard CORS declarations allow any website visited by a logged-in user to execute fetch commands against your server endpoints. This completely bypasses browser Same-Origin Policy (SOP).',
    attackScenario: 'A victim visits `attacker-domain.xyz`. The script runs a silent client-side AJAX fetch call to your server API `/api/profile` and leaks their cookies and session profile data.',
    recommendedFix: 'Establish a designated environment validation origin whitelist. Reject wildcard asterisk values for all authenticated API routes.',
    estimatedTime: '15 min',
    codeExample: `import cors from 'cors';\nimport express from 'express';\n\nconst app = express();\n\nconst WHITELISTED_DOMAINS = [\n  'https://app.audicode.io',\n  'https://dashboard.audicode.io'\n];\n\nconst corsOptions = {\n  origin: (origin: string | undefined, callback: Function) => {\n    if (!origin || WHITELISTED_DOMAINS.includes(origin)) {\n      callback(null, true);\n    } else {\n      callback(new Error('Cross-Origin Request Blocked by Security Policy'));\n    }\n  },\n  credentials: true,\n  optionsSuccessStatus: 200\n};\n\napp.use(cors(corsOptions));`
  },

  // 5. Direct Object Reference (Missing Ownership Checks - IDOR)
  'AUTH-MISSING-OWNERSHIP': {
    whyItMatters: 'Trusting a client-supplied identifier to update or query a database table without correlating it with caller account credentials results in Insecure Direct Object References.',
    attackScenario: 'An attacker logs into an account and alters their request parameters from `id=10` to `id=12`. The database serves notes belonging to a completely different tenant because caller validations are absent.',
    recommendedFix: 'Always include a composite filtering check inside your database query matching the unique primary key with the user identity decoded from JWT credentials.',
    estimatedTime: '15 min',
    codeExample: `// Unsafe: const note = await supabase.from('notes').select('*').eq('id', req.params.noteId);\n\n// Secure implementation checking current authenticated user ID:\nexport async function getNoteSecurely(req: any, res: any) {\n  const { noteId } = req.params;\n  const userId = req.user.id; // Resolved securely by requireAuth JWT middleware\n\n  const { data, error } = await supabase\n    .from('notes')\n    .select('*')\n    .eq('id', noteId)\n    .eq('user_id', userId) // Restrict selection to current caller ownership\n    .single();\n\n  if (error || !data) {\n    return res.status(404).json({ error: 'Resource not found or access denied.' });\n  }\n  return res.json(data);\n}`
  },

  // 6. Hardcoded Developer Credentials
  'AI-DEV-CREDENTIALS': {
    whyItMatters: 'Exposing plain passwords, database credentials, or third-party web credentials in source files risks fast exfiltration by crawlers or developers with minimal scoping rights.',
    attackScenario: 'A standard code commit exposes an active database host connection string. An automated script crawls the commit, connects to the exposed IP, and fully encrypts tables.',
    recommendedFix: 'Extract all static string literals. Push them to local environment variables declared inside secure `.env` structures and managed by key vaults.',
    estimatedTime: '5 min',
    codeExample: `// 1. Declare values in configuration .env file (not committed to VCS)\n// DB_CONNECT_STRING=postgresql://db_user:K9as_18ha#xs@db-host.internal:5432/main_db\n\n// 2. Consume configuration safely within application server code\nimport dotenv from 'dotenv';\ndotenv.config();\n\nconst dbUrl = process.env.DB_CONNECT_STRING;\nif (!dbUrl) {\n  throw new Error('CONFIG_ERROR: Crucial database parameters database connection is not set.');\n}\n\n// Initialize database pools with dbUrl...`
  },

  // 7. Dangerous Upload Handlers
  'API-DANGEROUS-UPLOAD': {
    whyItMatters: 'Accepting uploads with unvalidated client-supplied extensions and filenames allows scripts to overwrite static application boundaries, invoke remote shells, or plant HTML malware.',
    attackScenario: 'An attacker uploads a file named `backdoor.html` onto the assets server. They trigger a target URL directly through the browser, executing cross-site scripts inside client environments.',
    recommendedFix: 'Validate MIME structures against a strict whitelist, cap sizes, and rename destination files to UUIDs, bypassing user input entirely.',
    estimatedTime: '30 min',
    codeExample: `import multer from 'multer';\nimport path from 'path';\nimport { v4 as uuidv4 } from 'uuid';\n\nconst ALLOWED_MIMES = ['image/jpeg', 'image/png', 'application/pdf'];\n\nconst safeStorage = multer.diskStorage({\n  destination: './secure_uploads/',\n  filename: (req, file, cb) => {\n    // Use UUID to replace potentially malicious filename inputs entirely\n    const secureName = \`upload-\${uuidv4()}\${path.extname(file.originalname)}\`;\n    cb(null, secureName);\n  }\n});\n\nconst upload = multer({\n  storage: safeStorage,\n  limits: { fileSize: 2 * 1024 * 1024 }, // Max 2 Megabytes\n  fileFilter: (req, file, cb) => {\n    if (ALLOWED_MIMES.includes(file.mimetype)) {\n      cb(null, true);\n    } else {\n      cb(new Error('FILE_TYPE_ERROR: Invalid upload format rejected. Only JP/PNG/PDF permitted.'));\n    }\n  }\n});`
  },

  // 8. Command Injection
  'JS-EXEC': {
    whyItMatters: 'Spawning background commands using system string concatenation lets user input act as secondary sub-commands, inheriting host environment process permissions.',
    attackScenario: 'An attacker feeds the parameter `; rm -rf / ;` as an argument to a traceroute input form, deleting root file structures.',
    recommendedFix: 'Switch completely away from shell command string formatting. Use safe `execFile` or `spawn` containing parameter argument arrays.',
    estimatedTime: '30 min',
    codeExample: `// Unsafe: exec(\`ping -c 3 \${req.query.ip}\`) -> exposes system shell directly\n\n// Secure parameterization alternative using child_process.execFile:\nimport { execFile } from 'child_process';\nimport validator from 'validator';\n\nconst targetIp = req.query.ip;\nif (!validator.isIP(targetIp)) {\n  return res.status(400).json({ error: 'Malformed IP address payload input rejection.' });\n}\n\n// execFile executes the binary directly WITHOUT opening a system shell\nexecFile('ping', ['-c', '3', targetIp], (error, stdout, stderr) => {\n  if (error) {\n    return res.status(500).json({ error: 'Process execution error' });\n  }\n  return res.json({ result: stdout });\n});`
  },

  'JS-EXEC-SYNC': {
    whyItMatters: 'Executing shell commands synchronously blocks Node.js core event loops, yielding denial-of-service states while passing unvalidated arguments directly to host machines.',
    attackScenario: 'An attacker feeds intensive background task chains, triggering system bottlenecks that spike CPU to 100% and crash the service.',
    recommendedFix: 'Refactor to parameterized asynchronous execution binaries or dedicated platform library alternatives.',
    estimatedTime: '30 min',
    codeExample: `import { execFileSync } from 'child_process';\n\n// Secure parameterized asynchronous/sync limits: invoke exact executable\ntry {\n  const stdout = execFileSync('tar', ['-czf', 'backup.tar.gz', './source_dir'], {\n    timeout: 10000,\n    killSignal: 'SIGKILL'\n  });\n} catch (err) {\n  console.error("Task execution aborted");\n}`
  },

  // 9. Server Side Request Forgery (SSRF)
  'WEB-SSRF': {
    whyItMatters: 'Making backend HTTP requests to targets provided directly by client APIs permits users to scan internal networks, target loopbacks, or fetch cloud instance metadata templates.',
    attackScenario: 'An attacker supplies the target `http://169.254.169.254/latest/meta-data` as an image URL, fetching security access tokens for administrative AWS cloud assets.',
    recommendedFix: 'Enforce complete hostname parsing, discard private IP structures (such as RFC1918 blocks), and enforce strict target whitelists.',
    estimatedTime: '30 min',
    codeExample: `import { URL } from 'url';\nimport dns from 'dns/promises';\n\nexport async function fetchUserUrlSecure(userUrlStr: string) {\n  const parsed = new URL(userUrlStr);\n  const hostName = parsed.hostname;\n\n  // Convert hostname to active IP address before requests are issued\n  const addresses = await dns.resolve(hostName);\n  const resolvedIp = addresses[0];\n\n  const isPrivate = \n    resolvedIp.startsWith('127.') ||\n    resolvedIp.startsWith('10.') ||\n    resolvedIp.startsWith('192.168.') ||\n    resolvedIp.startsWith('172.16.') ||\n    resolvedIp === '169.254.169.254';\n\n  if (isPrivate) {\n    throw new Error('Forbidden: Attempted request targeting private CIDR namespace blocked.');\n  }\n\n  const response = await fetch(parsed.toString());\n  return response.text();\n}`
  },

  // 10. Insecure Path Traversal
  'WEB-PATH-TRAVERSAL': {
    whyItMatters: 'Resolving file paths on the file system using unvalidated arguments allows characters such as `../` to escape target sandbox enclosures and read deep operating system details.',
    attackScenario: 'An attacker parses parameter variables with `file=../../../../etc/passwd` and pulls critical operating system parameters.',
    recommendedFix: 'Discard relative traversal separators using `path.basename()` or verify absolute boundaries using resolved path matches.',
    estimatedTime: '30 min',
    codeExample: `import path from 'path';\nimport fs from 'fs';\n\nconst SAFE_DATA_DIRECTORY = path.resolve('/var/app/data');\n\nexport function resolveUserFileSecure(userInputFilename: string) {\n  // 1. Force filename isolation by discarding all directory parts\n  const baseName = path.basename(userInputFilename);\n  const resolvedTarget = path.join(SAFE_DATA_DIRECTORY, baseName);\n\n  // 2. Extra audit step: verify the final absolute path is nested within root directory\n  if (!resolvedTarget.startsWith(SAFE_DATA_DIRECTORY)) {\n    throw new Error('ACCESS_VIOLATION: Attempted directory tree traversal escape.');\n  }\n\n  return fs.readFileSync(resolvedTarget, 'utf-8');\n}`
  },

  // 11. Client Exposed AI Keys
  'SEC-EXPOSED-AI-KEY': {
    whyItMatters: 'Exposing AI provider strings (such as OpenAI or Gemini API keys) in public React interfaces yields massive coordinate thefts, uncontrolled billing spikes, and private token exhaustion.',
    attackScenario: 'A bot scrapes front-end bundles, isolates a key, and exhausts the budget with intensive GPT models.',
    recommendedFix: 'Refactor keys immediately out of front-end components. Route all AI request chains through backend server controllers.',
    estimatedTime: '5 min',
    codeExample: `// 1. REMOVE any keys from React views or .env prefix VITE_*\n// 2. Create Express Endpoint /api/chat proxying requests on Server\nimport { GoogleGenAI } from '@google/genai';\n\n// Backend loads secret server-side exclusively\nconst ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });\n\napp.post('/api/chat', async (req, res) => {\n  const { userPrompt } = req.body;\n  try {\n    const response = await ai.models.generateContent({\n      model: 'gemini-2.5-flash',\n      contents: userPrompt,\n    });\n    res.json({ reply: response.text });\n  } catch (err: any) {\n    res.status(500).json({ error: 'Proxy request generation failure' });\n  }\n});`
  },

  // 12. Giant Monolith Server
  'AI-GIANT-SERVER-FILE': {
    whyItMatters: 'AI programs frequently bundle thousands of lines of routers, credentials, and models into a single `server.ts` or `index.js`. This creates major compliance and state problems.',
    attackScenario: 'A small router error cascades, crashing the entire server since all business processes live in one monolith file.',
    recommendedFix: 'Subdivide the giant monolithic logic into distinct modular boundaries (folders like `/controllers`, `/routes`, and `/models`).',
    estimatedTime: 'Architectural Change',
    codeExample: `// Divide backend application structures logically into sub-folders:\n// - /server.ts (Entry point and express initialization only)\n// - /routes/auth.ts (Authorization controller routing)\n// - /routes/scans.ts (Scan controller routes)\n// - /controllers/auth.controller.ts (Business logic functions)\n// - /models/... (Database schema declarations)`
  },

  // 13. Giant Monolith React
  'AI-GIANT-REACT-COMPONENT': {
    whyItMatters: 'Placing all pages, states, charts, and configurations inside a single `App.tsx` file leads to rapid performance degradation and makes incremental features difficult to build.',
    attackScenario: 'Developers cannot modify layout components without triggering state re-renders across the entire interface, causing rendering delays.',
    recommendedFix: 'Isolate distinct display panels and modal configurations into dedicated functional components under `/src/components/*`.',
    estimatedTime: 'Architectural Change',
    codeExample: `// Break App.tsx into individual modular rendering layout components:\n// - /src/main.tsx (App registry and styling imports)\n// - /src/App.tsx (Context providers, router wrapper, page framework)\n// - /src/components/ReportView.tsx (Detailed scanner findings display)\n// - /src/components/DashboardView.tsx (Repository listing overview)`
  },

  // 14. Spaghetti Logic
  'AI-SPAGHETTI-LOGIC': {
    whyItMatters: 'Mixing database clients, security tokens, and JSX rendering directly inside React views bypasses controller routing security, exposing schema patterns to the client side.',
    attackScenario: 'A client-side build error exposes structural database parameters, making the database structure visible via browser inspect consoles.',
    recommendedFix: 'Decouple client schemas completely. Route data querying operations strictly via secure JSON API structures (/api/*).',
    estimatedTime: 'Architectural Change',
    codeExample: `// Decouple client React front-end components from database connection SDKs:\n// Unsafe: direct supabase client queries in component body\n// Secure:\n// 1. Back-end server exposes REST endpoint /api/notes\n// 2. Client queries endpoints safely using fetch:\nconst fetchNotes = async () => {\n  const res = await fetch('/api/notes', {\n    headers: { 'Authorization': \`Bearer \${token}\` }\n  });\n  return res.json();\n};`
  },

  // 15. Too many Empty Catch suppression blocks
  'AI-TRY-CATCH-SUPPRESSION': {
    whyItMatters: 'Using empty catch statements without error propagation suppresses runtime failures. This masks serious system-level errors and authentication problems.',
    attackScenario: 'Missing privileges fail silently inside an unlogged mock try block, leaving users wondering why their configurations do not load.',
    recommendedFix: 'Always include structured logging or re-throw exceptions to active application handlers.',
    estimatedTime: '5 min',
    codeExample: `// Unsafe: try { performCall() } catch(e) {} // Silent failure\n\n// Secure:\ntry {\n  await performCall();\n} catch (error: any) {\n  logger.error('CRITICAL: Operation failed execution', {\n    error: error.message,\n    context: 'Data Fetch Gateway'\n  });\n  // Trigger fallbacks or rethrow exception\n  throw new Error('System encountered an unrecoverable operation error.');\n}`
  },

  // DEFAULT FALLBACK REMEDIATION
  'DEFAULT': {
    whyItMatters: 'Treat this security boundary with strict static validation parameters. Unvetted inputs or loose variables expose the application layer to exploits.',
    attackScenario: 'An attacker manipulates parameters to bypass structural logical assumptions.',
    recommendedFix: 'Verify variable ranges, enforce type coercion, and sanitise parameters completely.',
    estimatedTime: '15 min',
    codeExample: `// Secure parameter sanitization and coercion pattern\nconst cleanParam = String(req.query.param || '').substring(0, 100).trim();\nif (!/^[a-zA-Z0-9_-]+$/.test(cleanParam)) {\n  throw new Error("Invalid request parameter layout");\n}`
  }
};

/**
 * Enriches a scanned finding with extensive fix details, real scenarios, and effort estimations.
 * All generation is fully deterministic, instant and local.
 */
export function enrichFindingWithFixDetails(finding: VulnerabilityInstance): VulnerabilityInstance {
  // Select matching template, fallback to generic DEFAULT or parent classes
  let template = REMEDIATION_CATALOG[finding.ruleId];

  if (!template) {
    // Check if the ruleId starts with specific categories (e.g. JS-EXEC, SEC-*, SQLI-*)
    if (finding.ruleId.startsWith('JS-EXEC') || finding.ruleId.startsWith('PY-CMD') || finding.ruleId.startsWith('GO-CMD') || finding.ruleId.startsWith('JAVA-CMD') || finding.ruleId.endsWith('CMD-INJ')) {
      template = REMEDIATION_CATALOG['JS-EXEC'];
    } else if (finding.ruleId.startsWith('SEC-AWS') || finding.ruleId.startsWith('SEC-GITHUB') || finding.ruleId.startsWith('SEC-SLACK') || finding.ruleId.startsWith('SEC-GENERIC') || finding.ruleId.startsWith('SEC-PEM')) {
      template = REMEDIATION_CATALOG['AI-DEV-CREDENTIALS'];
    } else if (finding.ruleId.startsWith('SQLI-RAW')) {
      template = {
        whyItMatters: 'Raw unparameterized SQL template queries format inputs directly into instructions. This allows attackers to run secondary commands, read tables, bypass logins, or drop database collections.',
        attackScenario: 'An attacker enters password payload fields containing `\' OR 1=1; --` and successfully logs in as the first user without a password check.',
        recommendedFix: 'Refactor raw queries to use prepared statement bindings or a structured query builder (ORM) that enforces dynamic parameters separation.',
        estimatedTime: '15 min',
        codeExample: `// Unsafe: db.query(\`SELECT * FROM users WHERE name = '\${req.body.name}'\`);\n\n// Secure prepared parameterized alternative using node-postgres:\nconst queryText = 'SELECT * FROM users WHERE name = $1';\nconst values = [req.body.name];\nconst result = await db.query(queryText, values);`
      };
    } else if (finding.ruleId.includes('XSS') || finding.ruleId.startsWith('JS-XSS')) {
      template = {
        whyItMatters: 'Rendering raw variables inside DOM structures without escaping allows attackers to inject malicious JavaScript. This can result in session hijacking, CSRF actions, or UI defacement.',
        attackScenario: 'An attacker enters `<iframe src="javascript:alert(document.cookie)">` in a comment field. The script executes on every client who views that page.',
        recommendedFix: 'Use front-end framework components that escape text outputs automatically (e.g., standard React curly brackets), or sanitize inputs through libraries like DOMPurify or sanitize-html.',
        estimatedTime: '15 min',
        codeExample: `// Unsafe: element.innerHTML = userComment;\n\n// Secure React implementation (escapes automatically):\nreturn <div>{userComment}</div>;\n\n// Secure raw HTML assignment using DOMPurify:\nimport DOMPurify from 'dompurify';\nconst cleanHtml = DOMPurify.sanitize(userComment);\nelement.innerHTML = cleanHtml;`
      };
    } else if (finding.ruleId.startsWith('JS-EVAL') || finding.ruleId.startsWith('JS-FUNCTION') || finding.ruleId.startsWith('PY-EVAL') || finding.ruleId.startsWith('PY-EXEC')) {
      template = {
        whyItMatters: 'Dynamic code execution (via eval, new Function, or exec) allows unvalidated text variables to execute directly in the JavaScript runtime compiler.',
        attackScenario: 'An attacker sends a payload containing `process.exit(1)` or file reading scripts, shutting down the hosting cluster.',
        recommendedFix: 'Always avoid eval. Replace with dynamic dictionary lookups, structured parser engines, or standard JSON.parse() methods.',
        estimatedTime: '30 min',
        codeExample: `// Unsafe: const res = eval(req.query.expression);\n\n// Secure mathematical expression evaluation using mathjs parser:\nimport { create, all } from 'mathjs';\nconst math = create(all);\nconst parser = math.parser();\n\ntry {\n  // Parse only safe arithmetic expressions, disabling function/object constructors\n  const result = parser.evaluate(req.query.expression);\n  res.json({ result });\n} catch (e) {\n  res.status(400).json({ error: 'Blocked: unsafe expression components.' });\n}`
      };
    } else if (finding.ruleId === 'OSV-DEPADVISORY') {
      template = {
        whyItMatters: 'Known outdated software models in dependencies are subject to public security advisories (CVEs). Attackers can launch known exploits to compromise host systems.',
        attackScenario: 'An attacker leverages public exploit code targeting minimized JSON parsing libraries to inject prototype pollution states.',
        recommendedFix: 'Update dependency declarations in `package.json` to recommended safe ranges.',
        estimatedTime: '15 min',
        codeExample: `// Update package.json to secure versions:\n// "minimist": ">=1.2.6"\n// "jsonwebtoken": ">=9.0.0"\n\n// Then run package installations:\n$ npm install`
      };
    } else {
      template = REMEDIATION_CATALOG['DEFAULT'];
    }
  }

  // Generate simulated attack/exploit steps
  const steps = getExploitSteps(finding.ruleId);

  // Extend the existing remediation structure
  return {
    ...finding,
    whyItMatters: template.whyItMatters,
    attackScenario: template.attackScenario,
    recommendedFix: template.recommendedFix,
    estimatedTime: template.estimatedTime,
    exploitSteps: steps,
    remediation: {
      beforeCode: finding.remediation?.beforeCode || finding.snippet,
      afterCode: template.codeExample // Populate with the code example
    }
  };
}

/**
 * Returns educational step-by-step impact simulations for critical/high vulnerabilities
 */
export function getExploitSteps(ruleId: string): { step: number; description: string; impact: string }[] {
  const normRule = ruleId.toUpperCase();
  
  if (normRule.includes('SUPABASE-MISSING-RLS')) {
    return [
      { step: 1, description: 'Extract public credentials (Supabase endpoint URL & client-anonymous API key) by inspecting local storage or main JS chunks in the browser DevTools.', impact: 'Unprivileged access to API keys.' },
      { step: 2, description: 'Construct direct HTTP requests bypassing any client-side components to target the exposed table: curl -H "apikey: sb-anon-key" https://project.supabase.co/rest/v1/tablename', impact: 'Direct API connection established.' },
      { step: 3, description: 'Fetch all rows successfully due to missing Row-Level Security checks on Postgres.', impact: 'Confidentiality breach; client-side data leaks.' },
      { step: 4, description: 'Issue PATCH and DELETE queries with administrative parameters to overwrite database entries or clear tables.', impact: 'Integrity loss; complete database compromise.' }
    ];
  }

  if (normRule.includes('FIREBASE-OPEN-RULES')) {
    return [
      { step: 1, description: 'Isolate public credentials configuration JSON from client static web builds, harvesting the Firestore Project ID.', impact: 'Acquisition of project connection endpoints.' },
      { step: 2, description: 'Initialize a direct connection to Firebase Firestore using a custom JS script or standard Firestore REST API nodes.', impact: 'Direct database communication channel established.' },
      { step: 3, description: 'Execute a read/query pipeline over generic root collections like "/users" or "/billing".', impact: 'Retrieving secure customer records without tokens.' },
      { step: 4, description: 'Execute write statements to rewrite active records or wipe collections using standard document deletions.', impact: 'Database defacement or complete metadata loss.' }
    ];
  }

  if (normRule.includes('JS-EXEC') || normRule.includes('PY-CMD') || normRule.includes('CMD-INJ')) {
    return [
      { step: 1, description: 'Analyze inputs (e.g. form fields, query params) that trigger background execution features (such as traceroute, image manipulation, or script compile).', impact: 'Identification of potential execution parameter.' },
      { step: 2, description: 'Submit malicious argument parameters containing shell command delimiters and control characters: e.g. "8.8.8.8; cat /etc/passwd" or "image.png | rm -rf ./*".', impact: 'Injecting custom interpreter instructions.' },
      { step: 3, description: 'The server executes Node.js subprocess commands using shell interpretation, running the injected statements alongside legitimate activities.', impact: 'Host machine remote code execution (RCE).' },
      { step: 4, description: 'Exfiltrate internal environment variables, spawn reverse shells back to attacker servers, or tamper with system boundaries.', impact: 'Total container and administrative workspace takeover.' }
    ];
  }

  if (normRule.includes('SQLI-RAW') || normRule.includes('SQL_INJECTION')) {
    return [
      { step: 1, description: 'Scan user login or filtering inputs where query data matches are formatted directly inside SQL string templates.', impact: 'Locating unparameterized query parameters.' },
      { step: 2, description: 'Formulate payload sequences with SQL syntax terminators: e.g. "\' OR \'1\'=\'1" or "test\'; DROP TABLE scan_reports; --".', impact: 'Modifying statements to alter query parsing logic.' },
      { step: 3, description: 'The PostgreSQL or relational database interprets the payload characters as active queries, bypassing verification gates entirely.', impact: 'Unauthorized access bypass and data access.' },
      { step: 4, description: 'Harvest passwords hashes, hijack admin records, or wipe entire systems.', impact: 'Arbitrary database command execution.' }
    ];
  }

  if (normRule.includes('AUTH-MISSING') || normRule.includes('ROUTE-UNPROTECTED')) {
    return [
      { step: 1, description: 'Scan JS routing networks or review client bundle declarations to map administrative server-side route directories (e.g. "/api/reports/all" or "/api/scans/:id").', impact: 'Detection of restricted API paths.' },
      { step: 2, description: 'Send raw HTTP requests lacking authorization tokens directly targeting those discovered administrative URLs.', impact: 'Targeting routes without credentials.' },
      { step: 3, description: 'The backend execution environment processes the route handler function since protective middleware guards are neglected.', impact: 'Unauthorized logic processing.' },
      { step: 4, description: 'Extract complete collections, download PDF files, or execute operations reserved for administrative users.', impact: 'System-wide data mining.' }
    ];
  }

  if (normRule.includes('CORS-OPEN') || normRule.includes('WEB-CORS-OPEN')) {
    return [
      { step: 1, description: 'An authenticated user logs in and remains active on your dashboard application.', impact: 'Valid active cookie session.' },
      { step: 2, description: 'The user is lured to visit an attacker-controlled external domain page containing high-contrast scripts.', impact: 'Host page context separation.' },
      { step: 3, description: 'The script issues a background cross-origin fetch request directing commands to your secure endpoint, passing "withCredentials" credentials.', impact: 'Browser submits local auth headers to target.' },
      { step: 4, description: 'Your server permits wildcard/reflect access. The browser exposes the confidential returned content directly to the attacker script.', impact: 'Stealing private session profile data.' }
    ];
  }

  if (normRule.includes('AUTH-MISSING-OWNERSHIP') || normRule.includes('IDOR')) {
    return [
      { step: 1, description: 'Log in as a standard user and execute normal CRUD calls, inspecting request parameters representing indexes (e.g., "?noteId=100").', impact: 'Identify linear index identifiers.' },
      { step: 2, description: 'Change parameters sequentially (e.g., "?noteId=101", "?noteId=102") using proxy tools or script loops.', impact: 'Access queries targeting adjacent records.' },
      { step: 3, description: 'The server retrieves items matching the ID param directly from SQL tables, lacking checks that link current user sessions with record owners.', impact: 'Bypassing access ownership restrictions.' },
      { step: 4, description: 'Read private data belonging to other users or compromise cross-tenant workspace files.', impact: 'Horizontal privilege escalation.' }
    ];
  }

  if (normRule.includes('DEV-CREDENTIALS') || normRule.includes('EXPOSED-AI-KEY')) {
    return [
      { step: 1, description: 'Perform static token pattern matches on code revisions, client build segments, or public repository distributions.', impact: 'Discovery of static confidential strings.' },
      { step: 2, description: 'Isolate plaintext credentials including AWS tokens, Postgres connection pools, OpenAI credentials, or Gemini API keys.', impact: 'Retrieval of production secrets.' },
      { step: 3, description: 'Initiate external calls using isolated keys to target official provider integrations directly.', impact: 'Impersonating administrative structures.' },
      { step: 4, description: 'Run intensive computational requests, exhaust credits, or trigger catastrophic service billing charges.', impact: 'Budget drainage and service disruption.' }
    ];
  }

  if (normRule.includes('PATH-TRAVERSAL')) {
    return [
      { step: 1, description: 'Audit image import or template viewer endpoints accepting dynamic paths (e.g. "/api/view?file=template.html").', impact: 'Locating filesystem endpoints.' },
      { step: 2, description: 'Submit path parameters modified to use parent directory operators: e.g. "../../../../../etc/passwd" or "../../../.env".', impact: 'Escaping target files directories.' },
      { step: 3, description: 'The file system resolver evaluates directory references, shifting upstream of the designated storage sandbox.', impact: 'Reading operating system configuration paths.' },
      { step: 4, description: 'Dump database credentials, configuration listings, or environment keys.', impact: 'Privileged file extraction.' }
    ];
  }

  // Fallback / default
  return [
    { step: 1, description: 'Audit endpoint operations and forms to intercept parameters.', impact: 'Identify logic hooks.' },
    { step: 2, description: 'Structure unvalidated parameters to trigger software logic errors or bypass boundary assumptions.', impact: 'Tamper with state parameters.' },
    { step: 3, description: 'The system executes the code block under unvetted configurations.', impact: 'Uncontrolled behavior.' },
    { step: 4, description: 'Exfiltrate confidential variables or trigger denial of service.', impact: 'Operational impact.' }
  ];
}
