import * as t from "@babel/types";
import type { NodePath } from "@babel/traverse";
import { getLineFromNode, getCodeSnippet, type Finding } from "./parser";

export interface SecurityRule {
  name: string;
  severity: "critical" | "high" | "medium" | "low";
  category: string;
  cwe: string;
  owasp: string;
  confidence: number;
  check: (path: NodePath, code: string) => Finding | null;
}

const FIXES: Record<string, string> = {
  "eval() Usage": "Avoid eval(), use JSON.parse() or Function constructor instead",
  "exec() Usage": "Use child_process.spawn() with arguments array",
  "Dangerous URI": "Validate and sanitize user input",
  "Hardcoded Secret": "Use environment variables or secrets manager",
  "SQL Injection": "Use parameterized queries or ORM",
  "Command Injection": "Use child_process.execFile() with arguments",
  "XSS Risk": "Use textContent or sanitize HTML",
  "Weak Crypto": "Use crypto.createHash('sha256')",
  "Insecure Random": "Use crypto.randomBytes() or crypto.randomUUID()",
  "Debug Mode": "Set DEBUG=False in production",
  "Wildcard CORS": "Specify allowed origins explicitly",
  "Path Traversal": "Validate and sanitize file paths",
  "eval() call": "Avoid eval(), use safer alternatives",
};

function getFix(name: string): string {
  return FIXES[name] || "Review and fix this code";
}

export const RULES: SecurityRule[] = [
  {
    name: "eval() Usage",
    severity: "critical",
    category: "Code Injection",
    cwe: "CWE-95",
    owasp: "A03",
    confidence: 90,
    check: (path: NodePath, code: string) => {
      const node = path.node;
      if (t.isCallExpression(node) && t.isIdentifier(node.callee)) {
        if (node.callee.name === "eval") {
          return {
            id: `eval-${getLineFromNode(node)}`,
            severity: "critical",
            title: "eval() Usage",
            description: "eval() is dangerous and can execute arbitrary code",
            file: "",
            line: getLineFromNode(node),
            code: getCodeSnippet(code, node),
            fix: getFix("eval() Usage"),
            category: "Code Injection",
            cwe: "CWE-95",
            owasp: "A03",
            confidence: 90,
          };
        }
      }
      return null;
    },
  },
  {
    name: "setTimeout with string",
    severity: "high",
    category: "Code Injection",
    cwe: "CWE-95",
    owasp: "A03",
    confidence: 85,
    check: (path: NodePath, code: string) => {
      const node = path.node;
      if (t.isCallExpression(node)) {
        const callee = node.callee;
        if (t.isIdentifier(callee) && callee.name === "setTimeout") {
          if (node.arguments.length > 0 && t.isStringLiteral(node.arguments[0])) {
            return {
              id: `settimeout-${getLineFromNode(node)}`,
              severity: "high",
              title: "setTimeout with string",
              description: "Passing string to setTimeout is like eval()",
              file: "",
              line: getLineFromNode(node),
              code: getCodeSnippet(code, node),
              fix: "Use arrow function: setTimeout(() => code, ms)",
              category: "Code Injection",
              cwe: "CWE-95",
              owasp: "A03",
              confidence: 85,
            };
          }
        }
      }
      return null;
    },
  },
  {
    name: "setInterval with string",
    severity: "high",
    category: "Code Injection",
    cwe: "CWE-95",
    owasp: "A03",
    confidence: 85,
    check: (path: NodePath, code: string) => {
      const node = path.node;
      if (t.isCallExpression(node)) {
        const callee = node.callee;
        if (t.isIdentifier(callee) && callee.name === "setInterval") {
          if (node.arguments.length > 0 && t.isStringLiteral(node.arguments[0])) {
            return {
              id: `setinterval-${getLineFromNode(node)}`,
              severity: "high",
              title: "setInterval with string",
              description: "Passing string to setInterval is like eval()",
              file: "",
              line: getLineFromNode(node),
              code: getCodeSnippet(code, node),
              fix: "Use arrow function: setInterval(() => code, ms)",
              category: "Code Injection",
              cwe: "CWE-95",
              owasp: "A03",
              confidence: 85,
            };
          }
        }
      }
      return null;
    },
  },
  {
    name: "Function constructor",
    severity: "high",
    category: "Code Injection",
    cwe: "CWE-95",
    owasp: "A03",
    confidence: 85,
    check: (path: NodePath, code: string) => {
      const node = path.node;
      if (t.isCallExpression(node) && t.isIdentifier(node.callee)) {
        if (node.callee.name === "Function") {
          return {
            id: `func-${getLineFromNode(node)}`,
            severity: "high",
            title: "Function constructor",
            description: "Function constructor is like eval()",
            file: "",
            line: getLineFromNode(node),
            code: getCodeSnippet(code, node),
            fix: "Use regular function or arrow function",
            category: "Code Injection",
            cwe: "CWE-95",
            owasp: "A03",
            confidence: 85,
          };
        }
      }
      return null;
    },
  },
  {
    name: "dangerouslySetInnerHTML",
    severity: "high",
    category: "XSS",
    cwe: "CWE-79",
    owasp: "A01",
    confidence: 95,
    check: (path: NodePath, code: string) => {
      const node = path.node;
      if (t.isMemberExpression(node)) {
        if (t.isIdentifier(node.property) && node.property.name === "dangerouslySetInnerHTML") {
          return {
            id: `xss-${getLineFromNode(node)}`,
            severity: "high",
            title: "XSS Risk",
            description: "dangerouslySetInnerHTML can cause XSS",
            file: "",
            line: getLineFromNode(node),
            code: getCodeSnippet(code, node),
            fix: "Sanitize HTML or use textContent",
            category: "XSS",
            cwe: "CWE-79",
            owasp: "A01",
            confidence: 95,
          };
        }
      }
      return null;
    },
  },
  {
    name: "innerHTML assignment",
    severity: "high",
    category: "XSS",
    cwe: "CWE-79",
    owasp: "A01",
    confidence: 85,
    check: (path: NodePath, code: string) => {
      const node = path.node;
      if (t.isAssignmentExpression(node)) {
        const left = node.left;
        if (t.isMemberExpression(left)) {
          if (t.isIdentifier(left.property) && left.property.name === "innerHTML") {
            return {
              id: `innerhtml-${getLineFromNode(node)}`,
              severity: "high",
              title: "innerHTML assignment",
              description: "Direct innerHTML can cause XSS",
              file: "",
              line: getLineFromNode(node),
              code: getCodeSnippet(code, node),
              fix: "Use textContent or sanitize input",
              category: "XSS",
              cwe: "CWE-79",
              owasp: "A01",
              confidence: 85,
            };
          }
        }
      }
      return null;
    },
  },
  {
    name: "Hardcoded API Key pattern",
    severity: "critical",
    category: "Secrets",
    cwe: "CWE-798",
    owasp: "A02",
    confidence: 90,
    check: (path: NodePath, code: string) => {
      const node = path.node;
      if (t.isVariableDeclarator(node) && node.init) {
        if (t.isStringLiteral(node.init) || t.isTemplateLiteral(node.init)) {
          let value = "";
          if (t.isStringLiteral(node.init)) {
            value = node.init.value;
          }
          if (t.isTemplateLiteral(node.init)) {
            value = node.init.quasis.map((q) => q.value.cooked).join("");
          }
          if (value && /^(sk-|ghp_|AKIA|eyJ|SK|AIza)/.test(value)) {
            return {
              id: `secret-${getLineFromNode(node)}`,
              severity: "critical",
              title: "Hardcoded Secret",
              description: "Possible hardcoded API key or token",
              file: "",
              line: getLineFromNode(node),
              code: getCodeSnippet(code, node),
              fix: "Use environment variables",
              category: "Secrets",
              cwe: "CWE-798",
              owasp: "A02",
              confidence: 90,
            };
          }
        }
      }
      return null;
    },
  },
  {
    name: "MD5 Hash",
    severity: "high",
    category: "Weak Crypto",
    cwe: "CWE-327",
    owasp: "A02",
    confidence: 90,
    check: (path: NodePath, code: string) => {
      const node = path.node;
      if (t.isCallExpression(node)) {
        const callee = node.callee;
        if (t.isMemberExpression(callee)) {
          if (t.isIdentifier(callee.property) && callee.property.name === "createHash") {
            if (t.isStringLiteral(node.arguments[0]) && node.arguments[0].value === "md5") {
              return {
                id: `md5-${getLineFromNode(node)}`,
                severity: "high",
                title: "Weak Crypto",
                description: "MD5 is cryptographically weak",
                file: "",
                line: getLineFromNode(node),
                code: getCodeSnippet(code, node),
                fix: "Use SHA-256 or stronger",
                category: "Weak Crypto",
                cwe: "CWE-327",
                owasp: "A02",
                confidence: 90,
              };
            }
          }
        }
      }
      return null;
    },
  },
  {
    name: "Math.random",
    severity: "high",
    category: "Insecure Random",
    cwe: "CWE-338",
    owasp: "A02",
    confidence: 80,
    check: (path: NodePath, code: string) => {
      const node = path.node;
      if (t.isMemberExpression(node)) {
        if (t.isIdentifier(node.object) && node.object.name === "Math") {
          if (t.isIdentifier(node.property) && node.property.name === "random") {
            return {
              id: `random-${getLineFromNode(node)}`,
              severity: "high",
              title: "Insecure Random",
              description: "Math.random() is not cryptographically secure",
              file: "",
              line: getLineFromNode(node),
              code: getCodeSnippet(code, node),
              fix: "Use crypto.randomBytes() or crypto.randomUUID()",
              category: "Insecure Random",
              cwe: "CWE-338",
              owasp: "A02",
              confidence: 80,
            };
          }
        }
      }
      return null;
    },
  },
];

export function applyRules(
  path: NodePath,
  code: string,
  filename: string
): Finding[] {
  const findings: Finding[] = [];

  for (const rule of RULES) {
    try {
      const finding = rule.check(path, code);
      if (finding) {
        finding.file = filename;
        findings.push(finding);
      }
    } catch (e) {
      // Skip rules that throw
    }
  }

  return findings;
}

export function createRuleVisitor(
  code: string,
  filename: string
): Record<string, any> {
  return {
    CallExpression(path: NodePath) {
      const findings = applyRules(path, code, filename);
    },
    MemberExpression(path: NodePath) {
      const findings = applyRules(path, code, filename);
    },
    AssignmentExpression(path: NodePath) {
      const findings = applyRules(path, code, filename);
    },
    VariableDeclarator(path: NodePath) {
      const findings = applyRules(path, code, filename);
    },
  };
}