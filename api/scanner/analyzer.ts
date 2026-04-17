import * as t from "@babel/types";
import type { NodePath } from "@babel/traverse";
import traverse from "@babel/traverse";
import { parseCode, type ParsedFile, type Finding } from "./parser";
import { applyRules, RULES } from "./rules";
import { createDefaultTaintTracker } from "./taint";
import { 
  getCodeContext, 
  calculateConfidence, 
  deduplicateFindings,
  isTestFile,
  type EvidenceFactors 
} from "./utils";

export interface FileAnalysis {
  file: string;
  language: string;
  findings: Finding[];
  error?: string;
}

export interface AnalysisResult {
  findings: Finding[];
  filesAnalyzed: number;
  errors: string[];
}

const SKIP_PATTERNS = [
  /node_modules/,
  /dist\//,
  /build\//,
  /\.git\//,
  /__pycache__/,
  /\.pytest_cache/,
  /vendor\//,
  /\.next\//,
  /\.nuxt\//,
  /\.test\./,
  /\.spec\./,
  /\.mock\./,
  /mock_/,
  /_mock\./,
];

const INCLUDE_EXTENSIONS = [
  ".js",
  ".jsx",
  ".ts",
  ".tsx",
  ".mjs",
  ".mts",
  ".py",
  ".rb",
  ".go",
  ".rs",
  ".java",
  ".kt",
  ".scala",
  ".php",
];

function shouldSkipFile(path: string): boolean {
  return SKIP_PATTERNS.some((pattern) => pattern.test(path));
}

function shouldIncludeFile(path: string): boolean {
  const ext = path.split(".").pop();
  return INCLUDE_EXTENSIONS.includes(`.${ext}`);
}

export function analyzeFile(
  code: string,
  filename: string
): FileAnalysis {
  const skipReason = shouldSkipFile(filename);

  if (skipReason) {
    return {
      file: filename,
      language: "unknown",
      findings: [],
      error: "Skipped by pattern",
    };
  }

  const parsed = parseCode(code, filename);
  const findings: Finding[] = [];

  if (parsed.errors.length > 0) {
    return {
      file: filename,
      language: parsed.language,
      findings: [],
      error: parsed.errors[0],
    };
  }

  if (parsed.ast) {
    const taintTracker = createDefaultTaintTracker();

    traverse(parsed.ast, {
      noScope: true,

      // A01: XSS
      CallExpression(path: NodePath) {
        const node = path.node;
        if (t.isIdentifier(node.callee)) {
          if (node.callee.name === "eval") {
            findings.push({
              id: `eval-${node.loc?.start.line}`,
              severity: "critical",
              title: "eval() Usage",
              description: "eval() is dangerous - arbitrary code execution",
              file: filename,
              line: node.loc?.start.line || 0,
              code: "eval(...)",
              fix: "Avoid eval(), use JSON.parse() or safe alternatives",
              category: "Injection",
              cwe: "CWE-95",
              owasp: "A03",
              confidence: 95,
            });
          }
          if (node.callee.name === "Function") {
            findings.push({
              id: `func-${node.loc?.start.line}`,
              severity: "high",
              title: "Function Constructor",
              description: "Function constructor is like eval()",
              file: filename,
              line: node.loc?.start.line || 0,
              code: "new Function(...)",
              fix: "Use regular function declaration",
              category: "Injection",
              cwe: "CWE-95",
              owasp: "A03",
              confidence: 90,
            });
          }
          // Command injection
          if (["exec", "execSync", "spawn"].includes(node.callee.name)) {
            findings.push({
              id: `cmd-${node.loc?.start.line}`,
              severity: "critical",
              title: "Command Injection",
              description: "exec/spawn can run shell commands",
              file: filename,
              line: node.loc?.start.line || 0,
              code: `${node.callee.name}(...)`,
              fix: "Use execFile with args array, avoid shell",
              category: "Injection",
              cwe: "CWE-78",
              owasp: "A03",
              confidence: 85,
            });
          }
        }
      },

      MemberExpression(path: NodePath) {
        const node = path.node;
        if (t.isIdentifier(node.property)) {
          // XSS - React
          if (node.property.name === "dangerouslySetInnerHTML") {
            findings.push({
              id: `xss-${node.loc?.start.line}`,
              severity: "high",
              title: "React XSS Risk",
              description: "dangerouslySetInnerHTML can cause XSS",
              file: filename,
              line: node.loc?.start.line || 0,
              code: "dangerouslySetInnerHTML",
              fix: "Sanitize HTML or use textContent",
              category: "XSS",
              cwe: "CWE-79",
              owasp: "A01",
              confidence: 95,
            });
          }
          // XSS - DOM
          if (node.property.name === "innerHTML") {
            findings.push({
              id: `innerhtml-${node.loc?.start.line}`,
              severity: "high",
              title: "innerHTML Assignment",
              description: "Direct innerHTML can cause XSS",
              file: filename,
              line: node.loc?.start.line || 0,
              code: ".innerHTML =",
              fix: "Use textContent or sanitize",
              category: "XSS",
              cwe: "CWE-79",
              owasp: "A01",
              confidence: 85,
            });
          }
          // Path traversal
          if (["readFile", "writeFile", "readFileSync", "writeFileSync", "createReadStream"].includes(node.property.name)) {
            findings.push({
              id: `pathtraversal-${node.loc?.start.line}`,
              severity: "high",
              title: "Path Traversal Risk",
              description: "File operations without path sanitization",
              file: filename,
              line: node.loc?.start.line || 0,
              code: `file.${node.property.name}`,
              fix: "Validate and sanitize file paths",
              category: "Path Traversal",
              cwe: "CWE-22",
              owasp: "A01",
              confidence: 70,
            });
          }
        }
      },

      AssignmentExpression(path: NodePath) {
        const node = path.node;
        if (t.isMemberExpression(node.left)) {
          const prop = t.isIdentifier(node.left.property) ? node.left.property.name : null;
          // XSS assignment
          if (prop === "innerHTML") {
            findings.push({
              id: `innerhtml-assign-${node.loc?.start.line}`,
              severity: "high",
              title: "innerHTML Assignment",
              description: "Direct innerHTML assignment can cause XSS",
              file: filename,
              line: node.loc?.start.line || 0,
              code: ".innerHTML = ...",
              fix: "Use textContent instead",
              category: "XSS",
              cwe: "CWE-79",
              owasp: "A01",
              confidence: 85,
            });
          }
        }
      },

      VariableDeclarator(path: NodePath) {
        const node = path.node;
        // Hardcoded secrets
        if (node.init && t.isStringLiteral(node.init)) {
          const value = node.init.value;
          if (value) {
            if (/^(sk-|ghp_|AKIA|eyJ|SK|AIza|xAI-|sk_live_)/.test(value)) {
              findings.push({
                id: `secret-${node.loc?.start.line}`,
                severity: "critical",
                title: "Hardcoded Secret",
                description: "Possible hardcoded API key or token",
                file: filename,
                line: node.loc?.start.line || 0,
                code: value.substring(0, 15) + "...",
                fix: "Use environment variables",
                category: "Secrets",
                cwe: "CWE-798",
                owasp: "A02",
                confidence: 95,
              });
            }
            if (/^-----BEGIN/.test(value)) {
              findings.push({
                id: `privatekey-${node.loc?.start.line}`,
                severity: "critical",
                title: "Private Key Exposed",
                description: "Private key found in source",
                file: filename,
                line: node.loc?.start.line || 0,
                code: "-----BEGIN PRIVATE KEY-----",
                fix: "Store in secrets manager",
                category: "Secrets",
                cwe: "CWE-798",
                owasp: "A02",
                confidence: 95,
              });
            }
          }
        }
      },

      CallExpression(path: NodePath) {
        const node = path.node;
        if (t.isMemberExpression(node.callee)) {
          // Weak crypto - MD5
          if (t.isIdentifier(node.callee.object) && 
              t.isIdentifier(node.callee.property) && 
              node.callee.object.name === "crypto") {
            if (node.callee.property.name === "createHash") {
              if (t.isStringLiteral(node.arguments[0])) {
                const algo = node.arguments[0].value;
                if (algo === "md5" || algo === "sha1") {
                  findings.push({
                    id: `weakhash-${node.loc?.start.line}`,
                    severity: "high",
                    title: `Weak Crypto (${algo.toUpperCase()})`,
                    description: `${algo.toUpperCase()} is cryptographically weak`,
                    file: filename,
                    line: node.loc?.start.line || 0,
                    code: `crypto.createHash('${algo}')`,
                    fix: "Use SHA-256 or stronger",
                    category: "Crypto",
                    cwe: "CWE-327",
                    owasp: "A02",
                    confidence: 90,
                  });
                }
              }
            }
          }
          // Insecure random
          if (t.isIdentifier(node.callee.object) && 
              t.isIdentifier(node.callee.property) &&
              node.callee.object.name === "Math" && 
              node.callee.property.name === "random") {
            findings.push({
              id: `insecure-random-${node.loc?.start.line}`,
              severity: "high",
              title: "Insecure Random",
              description: "Math.random() is not cryptographically secure",
              file: filename,
              line: node.loc?.start.line || 0,
              code: "Math.random()",
              fix: "Use crypto.randomUUID() or crypto.randomBytes()",
              category: "Crypto",
              cwe: "CWE-338",
              owasp: "A02",
              confidence: 85,
            });
          }
          // setTimeout/setInterval with string
          if (t.isIdentifier(node.callee.object) && 
              ["setTimeout", "setInterval"].includes(node.callee.object.name)) {
            if (node.arguments.length > 0 && t.isStringLiteral(node.arguments[0])) {
              findings.push({
                id: `timer-string-${node.loc?.start.line}`,
                severity: "high",
                title: `${node.callee.object.name} with String`,
                description: "String in timer is like eval()",
                file: filename,
                line: node.loc?.start.line || 0,
                code: `${node.callee.object.name}("...")`,
                fix: "Use arrow function: setTimeout(() => ..., ms)",
                category: "Injection",
                cwe: "CWE-95",
                owasp: "A03",
                confidence: 85,
              });
            }
          }
        }
      },
    } as any);
  }

  return {
    file: filename,
    language: parsed.language,
    findings,
  };
}

export function analyzeFiles(
  files: Array<{ path: string; content: string }>
): AnalysisResult {
  const allFindings: Finding[] = [];
  const errors: string[] = [];
  let filesAnalyzed = 0;

  for (const file of files) {
    filesAnalyzed++;
    const result = analyzeFile(file.content, file.path);

    if (result.error) {
      errors.push(`${file.path}: ${result.error}`);
    }

    for (const finding of result.findings) {
      finding.file = file.path;
      allFindings.push(finding);
    }
  }

  return {
    findings: allFindings,
    filesAnalyzed,
    errors,
  };
}