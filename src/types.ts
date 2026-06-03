/**
 * Shared Type Definitions for AudiCode Shell
 */

export interface GitHubUser {
  id: string;
  login: string;
  name: string | null;
  avatarUrl: string;
  accessToken: string;
  isSandbox?: boolean;
}

export interface Repository {
  id: string;
  name: string;
  owner: string;
  description: string;
  isPrivate: boolean;
  defaultBranch: string;
  url: string;
}

export interface UserSession {
  user: GitHubUser | null;
  isAuthenticated: boolean;
}

export interface TreeEntry {
  path: string;
  type: 'file' | 'directory';
  size?: number;
  extension?: string;
  depth: number;
}

export interface TreeResult {
  totalEntries: number;
  returnedEntries: number;
  truncated: boolean;
  entries: TreeEntry[];
}

export interface RankedTreeEntry {
  path: string;
  score: number;
  reasons: string[];
  extension?: string;
  depth: number;
  size?: number;
}

export interface RankingResult {
  profile: 'quick' | 'standard' | 'deep';
  totalEntries: number;
  rankedEntries: number;
  selectedEntries: RankedTreeEntry[];
  truncated: boolean;
  maxFilesScanned: number;
  maxTotalBytes: number;
  estimatedScanMs: number;
}

export interface FetchedFile {
  path: string;
  extension?: string;
  size: number;
  content: string;
  truncatedContent: boolean;
}

export interface ContentFetchResult {
  profile: 'quick' | 'standard' | 'deep';
  filesRequested: number;
  filesFetched: number;
  bytesFetched: number;
  truncated: boolean;
  skippedFiles: string[];
  files: FetchedFile[];
}

export type DetectionType = 'regex' | 'path' | 'config';
export type RuleSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type RuleCategory = 'secrets' | 'authentication' | 'authorization' | 'xss' | 'api-security' | 'supabase' | 'ai-security' | 'vercel';

export interface Rule {
  id: string;
  title: string;
  category: RuleCategory;
  severity: RuleSeverity;
  confidenceBase: number; // between 0.0 and 1.0
  aiEligible: boolean;
  appliesTo: string[]; // e.g. ['*.ts', '*.js', 'package.json'] or standard string extensions
  description: string;
  remediationTemplate: string;
  detectionType: DetectionType;
  patternString: string; // Serialized string of pattern or path or key config
}

export interface PromptPack {
  title: string;
  summary: string;
  risk: string;
  fixSteps: string[];
  aiRepairPrompt: string;
}

export interface Finding {
  id: string;
  ruleId: string;
  title: string;
  category: RuleCategory;
  severity: RuleSeverity;
  confidence: number;
  filePath: string;
  lineStart: number;
  lineEnd: number;
  evidence: string;
  explanation: string;
  remediation: string;
  promptPack: PromptPack;
}

export interface ScanSummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface ScanScope {
  filesScanned: number;
  filesSkipped: number;
  bytesScanned: number;
  partialScan: boolean;
  reasons: string[];
}

export interface ScanResult {
  scanId: string;
  profile: 'quick' | 'standard' | 'deep';
  summary: ScanSummary;
  scope: ScanScope;
  findings: Finding[];
  generatedAt: string;
}




