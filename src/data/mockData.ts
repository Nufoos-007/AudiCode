import { Vulnerability, AuditResult } from "../types/audit";

export const mockVulnerabilities: Vulnerability[] = [
  {
    id: "vuln-1",
    severity: "critical",
    title: "SQL Injection via unsanitized user input in login route",
    description:
      "User input is passed directly into a raw SQL query. An attacker can bypass authentication or dump your entire database by entering crafted strings like ' OR 1=1 --",
    file: "app/views/auth.py",
    line: 47,
    badCode: `query = f"SELECT * FROM users WHERE email = '{email}' AND password = '{password}'"`,
    fixedCode: `query = "SELECT * FROM users WHERE email = %s AND password = %s", (email, password)`,
  },
  {
    id: "vuln-2",
    severity: "high",
    title: "Hardcoded secret key in settings file",
    description:
      "Your Django SECRET_KEY is committed to the repo. Anyone with access to your code can forge session cookies and impersonate any user.",
    file: "config/settings.py",
    line: 23,
    badCode: `SECRET_KEY = "django-insecure-x7k!m3@p9q#r2s5t8v0w"`,
    fixedCode: `SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY")`,
  },
  {
    id: "vuln-3",
    severity: "medium",
    title: "No rate limiting on login endpoint",
    description:
      "Your login route accepts unlimited requests. An attacker can brute-force passwords without any restriction or lockout mechanism.",
    file: "app/urls.py",
    line: 12,
    badCode: `path("login/", views.login_view, name="login"),`,
    fixedCode: `path("login/", ratelimit("5/m")(views.login_view), name="login"),`,
  },
  {
    id: "vuln-4",
    severity: "low",
    title: "Missing Content-Security-Policy header",
    description:
      "No CSP header is set, allowing inline scripts and external resource loading. This increases XSS attack surface.",
    file: "middleware/security.py",
    line: 8,
    badCode: `# No CSP header configured`,
    fixedCode: `response["Content-Security-Policy"] = "default-src 'self'; script-src 'self'"`,
  },
  {
    id: "vuln-5",
    severity: "critical",
    title: "Exposed database credentials in environment file",
    description:
      "The .env file containing database credentials is tracked in git. Anyone who clones the repo gets full database access.",
    file: ".env",
    line: 3,
    badCode: `DATABASE_URL=postgres://admin:password123@db.example.com:5432/prod`,
    fixedCode: `# .env should be in .gitignore — use secrets manager`,
  },
  {
    id: "vuln-6",
    severity: "high",
    title: "Cross-Site Scripting (XSS) in user profile page",
    description:
      "User-supplied bio field is rendered without sanitization. Attackers can inject malicious scripts that execute in other users' browsers.",
    file: "templates/profile.html",
    line: 34,
    badCode: `<div>{{ user.bio | safe }}</div>`,
    fixedCode: `<div>{{ user.bio | escape }}</div>`,
  },
  {
    id: "vuln-7",
    severity: "critical",
    title: "Insecure deserialization of user-controlled data",
    description:
      "Using pickle to deserialize untrusted input can lead to arbitrary code execution on the server.",
    file: "utils/cache.py",
    line: 19,
    badCode: `data = pickle.loads(request.body)`,
    fixedCode: `data = json.loads(request.body)`,
  },
];

export const mockAuditResult: AuditResult = {
  repo: "user/vibe-coded-app",
  filesScanned: 847,
  scanTime: 28,
  score: 31,
  grade: "D",
  vulnerabilities: mockVulnerabilities,
  summary: {
    critical: mockVulnerabilities.filter((v) => v.severity === "critical").length,
    high: mockVulnerabilities.filter((v) => v.severity === "high").length,
    medium: mockVulnerabilities.filter((v) => v.severity === "medium").length,
    low: mockVulnerabilities.filter((v) => v.severity === "low").length,
  },
  credits: { used: 1, total: 2 },
};
