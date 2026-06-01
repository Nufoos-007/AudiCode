/**
 * Shared Type Definitions for AudiCode
 */

export type SeverityType = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export interface ASTNodeRef {
  filePath: string;
  startLine: number;
  endLine: number;
  startColumn: number;
  snippet: string;
}

export type TaintStatus = 'UNTAINTED' | 'TAINTED' | 'SANITIZED';

export interface VariableSymbol {
  id: string;              // Unique symbol ID within scope tracking
  name: string;            // Symbol identifier, e.g., "userData"
  scopeId: string;         // Reference to the lexical block ID
  status: TaintStatus;
  originNode?: ASTNodeRef;
  sanitizerRefs: string[]; // List of sanitizers applied to this symbol during propagation
}

export interface DFGEdge {
  fromSymbolId: string;
  toSymbolId: string;
  location: ASTNodeRef;
}

export interface ScopeContext {
  id: string;
  parentScopeId: string | null;
  symbols: Map<string, VariableSymbol>;
}

export interface SecurityRule {
  id: string;
  name: string;
  description: string;
  remediation: string;
  defaultSeverity: SeverityType;
  sources?: RegExp[];
  sinks?: string[];      // Known sink functions
  sanitizers?: string[];  // Known sanitizer methods
}

export interface TraceStep {
  stepIndex: number;
  nodeLocation: ASTNodeRef;
  symbolName: string;
  propagationSnippet: string;
}

export interface VulnerabilityInstance {
  id: string;
  ruleId: string;
  ruleName: string;
  severity: SeverityType;
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
  score: number;
  filePath: string;
  startLine: number;
  snippet: string;
  description: string;
  remediation: {
    beforeCode: string;
    afterCode: string;
  };
  dataFlowPath: TraceStep[];
  whyItMatters?: string;
  attackScenario?: string;
  recommendedFix?: string;
  estimatedTime?: '5 min' | '15 min' | '30 min' | '1 hour+' | 'Architectural Change';
  exploitSteps?: { step: number; description: string; impact: string }[];
  whyItTriggered?: string;
  confidenceScore?: number; // 40-99% based on AST, regex, correlation
  exploitability?: SeverityType; // exploiatbility rank
  sanitizationStatus?: 'Unsanitized' | 'Partially Sanitized' | 'Fully Sanitized';
  affectedVersion?: string;
  fixedVersion?: string;
  isGroupedDep?: boolean;
  packageName?: string;
  ecosystem?: string;
  advisories?: VulnerabilityInstance[];
}

export interface AttackChain {
  id: string;
  name: string;
  findingsUsed: { id: string; name: string; filePath: string; startLine: number }[];
  severity: SeverityType;
  businessImpact: string;
  exploitationDifficulty: 'EASY' | 'MEDIUM' | 'HARD';
  description: string;
}

export interface ScanReport {
  id: string;
  repositoryId: string;
  repositoryName: string;
  repositoryOwner: string;
  scannedAt: string;
  timeElapsedMs: number;
  totalFilesScanned: number;
  totalFilesDiscovered?: number;
  score: number; // Overall repo score (0-100)
  counts: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  findings: VulnerabilityInstance[];
  attackChains?: AttackChain[];
  frameworksDetected?: string[];
  aiGeneratedProbability?: number;
  aiRiskLevel?: 'LOW' | 'MEDIUM' | 'HIGH';
  aiArchitectureQuality?: 'EXCELLENT' | 'GOOD' | 'FAIR' | 'POOR';
  aiFactorsText?: string[];
  trustScore?: number;
  scannedFeatures?: { feature: string; status: 'Covered' | 'Not Scanned' }[];
  scannerSelfAudit?: {
    filesScannedList: string[];
    filesIgnoredList: string[];
    languagesDetected: string[];
    frameworksDetected: string[];
    scanDurationMs: number;
    detectionCoveragePercent: number;
  };
}

export interface Repository {
  id: string;
  name: string;
  owner: string;
  description: string | null;
  isPrivate: boolean;
  defaultBranch: string;
  url: string;
}

export interface GitHubUser {
  id: string;
  login: string;
  name: string | null;
  avatarUrl: string;
  accessToken: string;
  isSandbox?: boolean;
}

export interface UserSession {
  user: GitHubUser | null;
  isAuthenticated: boolean;
}
