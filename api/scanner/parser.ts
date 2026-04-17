import { parse, type File } from "@babel/parser";
import traverse from "@babel/traverse";
import * as t from "@babel/types";

export interface ParsedFile {
  path: string;
  ast: File | null;
  code: string;
  language: string;
  errors: string[];
}

export interface ASTResult {
  file: string;
  findings: Finding[];
}

export interface Finding {
  id: string;
  severity: "critical" | "high" | "medium" | "low";
  title: string;
  description: string;
  file: string;
  line: number;
  code: string;
  fix: string;
  category: string;
  cwe: string;
  owasp: string;
  confidence: number;
}

const EXTENSION_MAP: Record<string, string> = {
  js: "javascript",
  jsx: "javascript",
  ts: "typescript",
  tsx: "typescript",
  mjs: "javascript",
  mts: "typescript",
  py: "python",
  rb: "ruby",
  go: "go",
  rs: "rust",
  java: "java",
  kt: "kotlin",
  scala: "scala",
};

function getLanguage(filename: string): string {
  const ext = filename.split(".").pop()?.toLowerCase() || "";
  return EXTENSION_MAP[ext] || "unknown";
}

export { EXTENSION_MAP };

export function parseCode(code: string, filename: string): ParsedFile {
  const language = getLanguage(filename);
  const errors: string[] = [];

  let ast: File | null = null;
  let plugins: ("jsx" | "typescript" | "flow")[] = [];

  if (language === "typescript" || filename.endsWith(".tsx")) {
    plugins = ["jsx", "typescript"];
  } else if (language === "javascript" || filename.endsWith(".jsx")) {
    plugins = ["jsx"];
  }

  if (plugins.length > 0) {
    try {
      ast = parse(code, {
        sourceType: "module",
        plugins,
        errorRecovery: true,
      });
    } catch (e: any) {
      errors.push(`Parse error: ${e.message}`);
    }
  }

  return {
    path: filename,
    ast,
    code,
    language,
    errors,
  };
}

export function traverseAST(
  parsed: ParsedFile,
  visitor: Record<string, 
  any>
): ASTResult[] {
  const findings: Finding[] = [];

  if (!parsed.ast) {
    return [{ file: parsed.path, findings }];
  }

  traverse(parsed.ast, {
    noScope: true,
    ...visitor,
  } as any);

  return [{ file: parsed.path, findings }];
}

export function getCodeContext(
  code: string,
  line: number,
  context: number = 2
): string {
  const lines = code.split("\n");
  const start = Math.max(0, line - context - 1);
  const end = Math.min(lines.length, line + context);
  
  return lines.slice(start, end).join("\n");
}

export function getLineFromNode(node: t.Node): number {
  return node.loc?.start.line || 0;
}

export function getCodeSnippet(code: string, node: t.Node): string {
  const start = node.loc?.start.line || 1;
  const end = node.loc?.end.line || start;
  const lines = code.split("\n");
  
  if (start === end) {
    return lines[start - 1]?.substring(0, 100) || "";
  }
  
  return lines.slice(start - 1, end).join("\n").substring(0, 150);
}