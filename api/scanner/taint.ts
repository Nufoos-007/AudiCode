import * as t from "@babel/types";
import type { NodePath } from "@babel/traverse";
import type { Finding } from "./parser";

export interface TaintState {
  source: string;
  variable: string;
  line: number;
}

const TAINTED_FUNCTIONS = new Set([
  "eval",
  "exec",
  "spawn",
  "execSync",
  "execFile",
  "execFileSync",
  "writeFile",
  "writeFileSync",
]);

const INPUT_SOURCES: Record<string, string> = {
  "req.body": "Express request body",
  "req.query": "Express query params",
  "req.params": "Express path params",
  "req.headers": "Express headers",
  "process.argv": "Command line arguments",
  "process.env": "Environment variables",
  "fetch": "Network input",
  "readFile": "File input",
  "readdir": "File input",
};

export class TaintTracker {
  private taintedVars: Map<string, TaintState[]> = new Map();
  private trackedVars: Set<string> = new Set();

  clear(): void {
    this.taintedVars.clear();
    this.trackedVars.clear();
  }

  trackVariable(name: string, source: string, line: number): void {
    this.trackedVars.add(name);
    const existing = this.taintedVars.get(name) || [];
    existing.push({ source, variable: name, line });
    this.taintedVars.set(name, existing);
  }

  isTainted(name: string): boolean {
    return this.taintedVars.has(name);
  }

  getTaintedVars(): string[] {
    return Array.from(this.taintedVars.keys());
  }

  markFromMemberExpression(path: NodePath): Finding | null {
    const node = path.node;
    if (!t.isMemberExpression(node)) return null;

    const objName = t.isIdentifier(node.object) ? node.object.name : null;
    const propName = t.isIdentifier(node.property) ? node.property.name : null;

    if (objName && propName) {
      const key = `${objName}.${propName}`;
      if (INPUT_SOURCES[key]) {
        if (t.isVariableDeclarator(path.parent)) {
          const varName = t.isIdentifier(path.parent.id) ? path.parent.id.name : null;
          if (varName) {
            this.trackVariable(varName, key, node.loc?.start.line || 0);
          }
        }
      }
    }

    return null;
  }

  markFromCallExpression(path: NodePath): Finding | null {
    const node = path.node;
    if (!t.isCallExpression(node)) return null;

    const callee = node.callee;
    let funcName: string | null = null;

    if (t.isIdentifier(callee)) {
      funcName = callee.name;
    } else if (t.isMemberExpression(callee)) {
      funcName = t.isIdentifier(callee.property) ? callee.property.name : null;
    }

    if (funcName && TAINTED_FUNCTIONS.has(funcName)) {
      for (const arg of node.arguments) {
        if (t.isIdentifier(arg)) {
          if (this.isTainted(arg.name)) {
            return {
              id: `taint-${arg.name}-${node.loc?.start.line}`,
              severity: "critical",
              title: "Tainted Input to Dangerous Function",
              description: `Using user input in ${funcName}()`,
              file: "",
              line: node.loc?.start.line || 0,
              code: "",
              fix: `Validate and sanitize ${arg.name} before using in ${funcName}`,
              category: "Code Injection",
              cwe: "CWE-95",
              owasp: "A03",
              confidence: 80,
            };
          }
        }
      }
    }

    return null;
  }

  createVisitor(): Record<string, any> {
    const tracker = this;
    return {
      CallExpression(path: NodePath) {
        path.skip();
        const finding = tracker.markFromCallExpression(path);
      },
      MemberExpression(path: NodePath) {
        const finding = tracker.markFromMemberExpression(path);
      },
    };
  }
}

export function createDefaultTaintTracker(): TaintTracker {
  return new TaintTracker();
}