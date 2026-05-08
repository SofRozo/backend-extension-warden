import {
  RiskLevel,
  FindingCategory,
  DetonationStrategy,
  PlatformLevel,
} from '../enums/risk-level.enum.js';

// ─── Preprocessor types ───────────────────────────────────────────────────────

export type FileRole = 'content_script' | 'background' | 'popup' | 'library' | 'unknown';

export interface ExtractedChromeApi {
  api: string;
  line: number;
}

export interface ExtractedDomain {
  domain: string;
  line: number;
}

export interface ProcessedFile {
  path: string;
  role: FileRole;
  isObfuscated: boolean;
  cleanCode?: string;
  urls: string[];
  domains: ExtractedDomain[];
  chromeApis: ExtractedChromeApi[];
  usesFetch: boolean;
  usesXHR: boolean;
  usesEval: boolean;
  usesDomManipulation: boolean;
}

export interface ManifestInfo {
  manifestVersion: 2 | 3;
  name: string;
  version: string;
  description?: string;
  author?: string;
  apiPermissions: string[];
  hostPermissions: string[];
  contentScripts: Array<{
    matches: string[];
    js: string[];
    css?: string[];
  }>;
  backgroundScripts: string[];
  serviceWorker?: string;
  popupUrl?: string;
  rawManifest: Record<string, unknown>;
}

export interface RemoteCodeViolation {
  htmlFile: string;
  externalSrc: string;
}

export interface PreprocessorOutput {
  crxHash: string;
  extractPath: string;
  manifest: ManifestInfo;
  files: ProcessedFile[];
  obfuscatedFileCount: number;
  hasObfuscation: boolean;
  /** MV3 policy violations: HTML files that load external <script src="https://..."> */
  remoteCodeViolations: RemoteCodeViolation[];
}

export interface StaticFinding {
  category: FindingCategory;
  pattern: string;
  description: string;
  severity: RiskLevel;
  location: {
    file: string;
    line: number;
    column: number;
  };
  codeSnippet?: string;
}

export interface DiscoveredDomain {
  domain: string;
  source: 'code' | 'manifest';
  context: string;
  platformLevel: PlatformLevel;
  category?: string;
}

export interface DomSelector {
  selector: string;
  method: string;
  file: string;
  line: number;
}

export interface NetworkRequest {
  url: string;
  method: string;
  headers: Record<string, string>;
  body?: string;
  timestamp: number;
  origin: 'extension' | 'browser' | 'unknown';
  initiator?: string;
  context?: string;
}

export interface DomMutation {
  type: string;
  target: string;
  value?: string;
  timestamp: number;
  context?: string;
}

export interface KeyboardEvent {
  type: string;
  key?: string;
  timestamp: number;
  target?: string;
  context?: string;
}

export interface ApiCall {
  api: string;       // e.g. "chrome.storage.local.set"
  args: string;      // JSON-serialized arguments (truncated)
  timestamp: number;
  context?: string;
}

export interface DynamicEvidence {
  networkRequests: NetworkRequest[];
  domMutations: DomMutation[];
  keyboardEvents: KeyboardEvent[];
  apiCalls: ApiCall[];
  screenshotPaths?: string[];
  logs?: Array<{ module: string; message: string; level: string; timestamp: number }>;
}

export interface StaticAnalysisResult {
  findings: StaticFinding[];
  discoveredDomains: DiscoveredDomain[];
  domSelectors: DomSelector[];
  manifestPermissions: string[];
  manifestHostPermissions: string[];
  crxHash: string;
  obfuscationDetected: boolean;
  deobfuscationApplied: boolean;
}

export interface SandboxDomainObservation {
  domain: string;
  url: string;
  observations: string[];
  actionsPerformed: string[];
  requestsToThisDomain: number;
  domModificationsDetected: boolean;
  credentialsSubmitted: boolean;
  verdicto?: 'benigna' | 'sospechosa' | 'maliciosa';
  error?: string;
}

export interface DynamicAnalysisResult {
  strategy: DetonationStrategy;
  evidence: DynamicEvidence;
  containerId?: string;
  duration: number;
  timedOut: boolean;
  // Agent-driven sandbox fields (populated when Agent 2 provides domain list)
  extensionVerified?: boolean;
  domainObservations?: SandboxDomainObservation[];
}

export interface ThreatIntelResult {
  domain: string;
  provider: string;
  isMalicious: boolean;
  score?: number;
  categories?: string[];
  details?: Record<string, unknown>;
  queriedAt: Date;
}

export interface PrivacyLabel {
  category: string;
  title: string;
  description: string;
  severity: RiskLevel;
  evidence: string[];
}

export interface ContactedUrlReputation {
  url: string;
  hostname: string;
  isMalicious: boolean;
  score: number;
  providers: string[];       // which threat intel providers flagged it
  categories: string[];
}

export interface AnnotatedPermission {
  name: string;
  description: string;
  category: string;
  risk: RiskLevel;
  isAbused: boolean;
}

// ─── AI Agent results ─────────────────────────────────────────────────────────
// Imported as a type-only alias to avoid circular deps with the agents module.
// The full types live in src/agents/interfaces/agents.interfaces.ts.

export interface AgentAnalysisResult {
  agent1: any | null;
  agent2: any | null;
  agent3: any | null;
  agent4?: any | null;
  ranSuccessfully: boolean;
  errors: string[];
}

export interface AnalysisReport {
  jobId: string;
  extensionId: string;
  extensionName?: string;
  extensionVersion?: string;
  extensionAuthor?: string;
  crxHash: string;
  overallRisk: RiskLevel;
  privacyLabels: PrivacyLabel[];
  staticFindings: StaticFinding[];
  dynamicEvidence?: DynamicEvidence;
  threatIntelResults: ThreatIntelResult[];
  contactedUrls: string[];
  contactedUrlsReputation: ContactedUrlReputation[];
  abusedPermissions: string[];
  annotatedPermissions: AnnotatedPermission[];
  recommendation: string;
  analysisTimestamp: Date;
  analysisDuration: number;
  confidence: number;
  score1: number; // Attack Surface (Permissions only)
  score2: number; // Contextual Risk (Static AI)
  score3: number; // Confirmed Risk (Dynamic AI)
  agentAnalysis?: AgentAnalysisResult;
  testResults?: Array<{
    name: string;
    status: 'PASSED' | 'FAILED' | 'SKIPPED';
    description: string;
    severity: RiskLevel;
    findings: string[];
  }>;
}
