export type Severity = "critical" | "high" | "medium" | "low";

export interface Vulnerability {
  id: string;
  severity: Severity;
  title: string;
  description: string;
  file: string;
  line: number;
  badCode: string;
  fixedCode: string;
}

export interface AuditResult {
  repo: string;
  filesScanned: number;
  scanTime: number;
  score: number;
  grade: string;
  vulnerabilities: Vulnerability[];
  summary: Record<Severity, number>;
  credits: { used: number; total: number };
}
