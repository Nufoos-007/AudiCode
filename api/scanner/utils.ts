import type { Finding } from "./parser";

export function getCodeContext(
  code: string,
  line: number,
  context: number = 5
): string {
  const lines = code.split("\n");
  const start = Math.max(0, line - context - 1);
  const end = Math.min(lines.length, line + context);
  
  if (start >= end) return "";
  
  const contextLines = lines.slice(start, end);
  return contextLines
    .map((l, i) => {
      const lineNum = start + i + 1;
      const marker = lineNum === line ? "👉 " : "   ";
      return `${marker}${lineNum}: ${l}`;
    })
    .join("\n");
}

export function getParentFunction(
  code: string,
  line: number
): string | null {
  const lines = code.split("\n");
  const before = Math.max(0, line - 1);
  const after = Math.min(lines.length, line + 5);
  
  let depth = 0;
  let funcStart = -1;
  
  for (let i = before; i >= 0; i--) {
    const l = lines[i];
    if (l.includes("function") || l.includes("=>") || l.includes("async ")) {
      funcStart = i;
      break;
    }
  }
  
  if (funcStart === -1) return null;
  
  return lines.slice(funcStart, after).join("\n");
}

export interface EvidenceFactors {
  isDirectCall: boolean;
  isUserInput: boolean;
  isTestFile: boolean;
  isCommentedCode: boolean;
  hasFixAvailable: boolean;
  severity: "critical" | "high" | "medium" | "low";
}

export function calculateConfidence(factors: EvidenceFactors): number {
  let score = 50;

  if (factors.isDirectCall) score += 30;
  if (factors.isUserInput) score += 20;
  if (factors.severity === "critical") score += 15;
  if (factors.severity === "high") score += 10;
  if (factors.isTestFile) score -= 25;
  if (factors.isCommentedCode) score -= 30;
  if (factors.hasFixAvailable) score += 10;

  return Math.min(95, Math.max(40, score));
}

export function deduplicateFindings(
  findings: Finding[]
): Finding[] {
  const grouped = new Map<string, Finding[]>();
  
  for (const finding of findings) {
    const key = `${finding.title}-${finding.file}-${finding.category}`;
    const existing = grouped.get(key) || [];
    existing.push(finding);
    grouped.set(key, existing);
  }

  const deduplicated: Finding[] = [];
  
  for (const [_, group] of grouped) {
    if (group.length === 1) {
      deduplicated.push(group[0]);
    } else {
      const first = { ...group[0] };
      first.id = `${first.id}-${group.length}x`;
      first.description = `${first.description} (${group.length} occurrences)`;
      first.confidence = Math.min(95, first.confidence + group.length * 2);
      deduplicated.push(first);
    }
  }

  return deduplicated;
}

export function isTestFile(filename: string): boolean {
  return /(\.test\.|\.spec\.|\.mock\.|_test\.|_spec\.)/.test(filename);
}

export function isUserInput(varName: string): boolean {
  const inputPatterns = [
    /req\./,
    /body/i,
    /query/i,
    /params/i,
    /input/i,
    /body/,
    /argv/,
  ];
  return inputPatterns.some(p => p.test(varName));
}

export function isCommentedCode(code: string, line: number): boolean {
  const lines = code.split("\n");
  const targetLine = lines[line - 1]?.trim() || "";
  return targetLine.startsWith("//") || 
         targetLine.startsWith("/*") || 
         targetLine.startsWith("*") ||
         targetLine.startsWith("#");
}