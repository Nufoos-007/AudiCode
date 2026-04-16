import * as t from "@babel/types";
import type { NodePath } from "@babel/traverse";
import traverse from "@babel/traverse";
import { parseCode, type ParsedFile, type Finding } from "./parser";
import { applyRules, RULES } from "./rules";
import { createDefaultTaintTracker } from "./taint";

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

      CallExpression(path: NodePath) {
        const node = path.node;
        if (t.isIdentifier(node.callee)) {
          if (node.callee.name === "eval") {
            findings.push({
              id: `eval-${node.loc?.start.line}`,
              severity: "critical",
              title: "eval() Usage",
              description: "eval() is dangerous",
              file: filename,
              line: node.loc?.start.line || 0,
              code: "eval(...)",
              fix: "Avoid eval()",
              category: "Injection",
              cwe: "CWE-95",
              owasp: "A03",
              confidence: 90,
            });
          }
        }

        if (t.isIdentifier(node.callee) && node.callee.name === "Function") {
          findings.push({
            id: `func-${node.loc?.start.line}`,
            severity: "high",
            title: "Function Constructor",
            description: "Function constructor is like eval()",
            file: filename,
            line: node.loc?.start.line || 0,
            code: "new Function(...)",
            fix: "Use regular function",
            category: "Injection",
            cwe: "CWE-95",
            owasp: "A03",
            confidence: 85,
          });
        }
      },

      MemberExpression(path: NodePath) {
        const node = path.node;
        if (t.isIdentifier(node.property)) {
          if (node.property.name === "dangerouslySetInnerHTML") {
            findings.push({
              id: `xss-${node.loc?.start.line}`,
              severity: "high",
              title: "React XSS Risk",
              description: "dangerouslySetInnerHTML can cause XSS",
              file: filename,
              line: node.loc?.start.line || 0,
              code: "dangerouslySetInnerHTML",
              fix: "Sanitize or use textContent",
              category: "XSS",
              cwe: "CWE-79",
              owasp: "A01",
              confidence: 95,
            });
          }

          if (node.property.name === "innerHTML") {
            findings.push({
              id: `innerhtml-${node.loc?.start.line}`,
              severity: "high",
              title: "innerHTML Assignment",
              description: "Direct innerHTML can cause XSS",
              file: filename,
              line: node.loc?.start.line || 0,
              code: ".innerHTML =",
              fix: "Use textContent",
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
        if (node.init && t.isStringLiteral(node.init)) {
          const value = node.init.value;
          if (value && /^(sk-|ghp_|AKIA|eyJ|SK|AIza)/.test(value)) {
            findings.push({
              id: `secret-${node.loc?.start.line}`,
              severity: "critical",
              title: "Hardcoded Secret",
              description: "Possible hardcoded API key or token",
              file: filename,
              line: node.loc?.start.line || 0,
              code: value.substring(0, 20) + "...",
              fix: "Use environment variables",
              category: "Secrets",
              cwe: "CWE-798",
              owasp: "A02",
              confidence: 90,
            });
          }
        }
      },

      CallExpression(path: NodePath) {
        const node = path.node;
        if (t.isMemberExpression(node.callee)) {
          if (t.isIdentifier(node.callee.object) && node.callee.object.name === "Math") {
            if (t.isIdentifier(node.callee.property) && node.callee.property.name === "random") {
              findings.push({
                id: `random-${node.loc?.start.line}`,
                severity: "high",
                title: "Insecure Random",
                description: "Math.random() is not cryptographically secure",
                file: filename,
                line: node.loc?.start.line || 0,
                code: "Math.random()",
                fix: "Use crypto.randomUUID()",
                category: "Crypto",
                cwe: "CWE-338",
                owasp: "A02",
                confidence: 80,
              });
            }
          }
        }
      },

      CallExpression(path: NodePath) {
        const node = path.node;
        if (t.isMemberExpression(node.callee)) {
          if (t.isIdentifier(node.callee.property) && node.callee.property.name === "createHash") {
            if (t.isStringLiteral(node.arguments[0]) && node.arguments[0].value === "md5") {
              findings.push({
                id: `md5-${node.loc?.start.line}`,
                severity: "high",
                title: "Weak Crypto",
                description: "MD5 is cryptographically weak",
                file: filename,
                line: node.loc?.start.line || 0,
                code: "crypto.createHash('md5')",
                fix: "Use SHA-256",
                category: "Crypto",
                cwe: "CWE-327",
                owasp: "A02",
                confidence: 90,
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