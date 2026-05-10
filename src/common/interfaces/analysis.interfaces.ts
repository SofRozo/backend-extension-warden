import { DetonationStrategy } from '../enums/risk-level.enum.js';
import type {
  Agent1Output,
  DomainCategory,
} from '../../agents/interfaces/agents.interfaces.js';

// ─── File classification ─────────────────────────────────────────────────────

export type FileRole =
  | 'content_script'
  | 'background'
  | 'popup'
  | 'library'
  | 'unknown'
  | 'manifest';

// ─── Preprocessor: per-file extracted data ───────────────────────────────────

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

// ─── Manifest ────────────────────────────────────────────────────────────────

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

// ─── Resultado 1 — Static findings (NO URLs) ─────────────────────────────────

/**
 * Discovery types for Resultado 1 (everything that is NOT a URL/domain).
 * Each finding is uniformly shaped as { fileType, filePath, discoveryType, detail, line }.
 */
export type StaticDiscoveryType =
  | 'permiso_chrome_manifest_no_usado'
  | 'uso_api_chrome'
  | 'funcion_javascript_riesgosa'
  | 'flujo_datos_a_red'
  | 'codigo_ofuscado'
  | 'script_remoto_mv3'
  | 'listener_teclado'
  | 'inyeccion_dom'
  | 'lectura_cookies'
  | 'lectura_storage_navegador';

export interface PreprocessingFinding {
  fileType: FileRole;
  filePath: string;
  discoveryType: StaticDiscoveryType;
  /** Concrete subject — e.g. "chrome.cookies.getAll", "eval", "innerHTML", "keydown", "cookies" */
  detail: string;
  line: number;
  /** Optional code snippet to help the agent reason */
  codeSnippet?: string;
}

// ─── Resultado 2 — URL/domain findings ───────────────────────────────────────

export type DomainDiscoveryType =
  | 'url_en_codigo'
  | 'host_permission_manifest';

export interface DomainFinding {
  fileType: FileRole;
  filePath: string;
  discoveryType: DomainDiscoveryType;
  domain: string;
  category: DomainCategory;
  /**
   * Visit priority. Defined only for sensitive categories (financiero, identidad,
   * llm, correo, redes, gob). Lower number = visited first.
   */
  priority?: number;
  line: number;
}

// ─── Preprocessor output (top-level) ─────────────────────────────────────────

export interface PreprocessorOutput {
  crxHash: string;
  extractPath: string;
  manifest: ManifestInfo;
  files: ProcessedFile[];
  obfuscatedFileCount: number;
  hasObfuscation: boolean;
  /** MV3 policy violations — also surfaced as PreprocessingFinding entries */
  remoteCodeViolations: RemoteCodeViolation[];
  /** Resultado 1 — every static finding that is NOT a URL */
  resultado1: PreprocessingFinding[];
  /** Resultado 2 — sensitive domains (financiero, identidad, llm, correo, redes, gob) */
  resultado2_priority: DomainFinding[];
  /** Resultado 2 — domains that need LLM/threat-intel reasoning (desconocido) */
  resultado2_unknown: DomainFinding[];
}

// ─── Dynamic analysis ────────────────────────────────────────────────────────

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
  api: string;
  args: string;
  timestamp: number;
  context?: string;
}

export interface DynamicEvidence {
  networkRequests: NetworkRequest[];
  domMutations: DomMutation[];
  keyboardEvents: KeyboardEvent[];
  apiCalls: ApiCall[];
  logs?: Array<{
    module: string;
    message: string;
    level: string;
    timestamp: number;
  }>;
}

/**
 * Stagehand observation per priority domain — raw signals collected by the
 * navigator (Stagehand or IntelligentNavigator) before Agent 4 verdicts them.
 */
export interface SandboxDomainObservation {
  domain: string;
  url: string;
  /** Which agent drove Playwright on this domain — useful to compare runs. */
  navigatorUsed: 'stagehand' | 'intelligent_navigator';
  observations: string[];
  actionsPerformed: string[];
  /**
   * Per-step timeline emitted by the agent. Each entry includes the LLM's
   * decision (action + reasoning) and the result of executing it.
   */
  agentSteps: AgentStep[];
  requestsToThisDomain: number;
  domModificationsDetected: boolean;
  credentialsSubmitted: boolean;
  /** True when the navigator injected a storageState cookie file */
  honeypotSessionUsed: boolean;
  error?: string;
}

export interface AgentStep {
  step: number;
  /** What the agent perceived from the page */
  observation: string;
  /** Action proposed by the LLM: 'click' | 'type' | 'navigate' | 'wait' | 'observe' | 'extract' | 'done' */
  action: string;
  /** Element/value targeted by the action */
  target?: string;
  /** LLM's stated reasoning for this decision */
  reasoning: string;
  /** Outcome of executing the action: 'success' | 'failed' | 'no-op' */
  result: string;
  timestamp: number;
}

export interface DynamicAnalysisResult {
  strategy: DetonationStrategy;
  evidence: DynamicEvidence;
  containerId?: string;
  duration: number;
  timedOut: boolean;
  extensionVerified?: boolean;
  domainObservations?: SandboxDomainObservation[];
}

// ─── Threat Intel ────────────────────────────────────────────────────────────

export interface ThreatIntelResult {
  domain: string;
  provider: string;
  isMalicious: boolean;
  score?: number;
  categories?: string[];
  details?: Record<string, unknown>;
  queriedAt: Date;
}

// ─── Verdicted findings (output of agents 2/3/4) ─────────────────────────────

export type VerdictPositive = 'positivo' | 'falso_positivo';
export type DynamicVerdict = 'maliciosa' | 'sospechosa' | 'benigna' | 'inaccesible';

export interface VerdictedStaticFinding extends PreprocessingFinding {
  veredicto: VerdictPositive;
  razon: string;
}

export interface VerdictedDomainFinding extends DomainFinding {
  veredicto: VerdictPositive;
  razon: string;
  /** Threat-intel snippet shown to the LLM for unknown domains */
  threatIntelSummary?: string;
}

export interface DynamicVerdictedFinding extends DomainFinding {
  veredicto: DynamicVerdict;
  accion_hecha: string;
  razon: string;
}

// ─── Combined agent results ──────────────────────────────────────────────────

export interface AgentAnalysisResult {
  agent1: Agent1Output | null;
  /** Resultado 1 con veredicto+razón por hallazgo */
  agent2: VerdictedStaticFinding[] | null;
  /** Resultado 2 (priority + unknown) con veredicto+razón */
  agent3: {
    priority: VerdictedDomainFinding[];
    unknown: VerdictedDomainFinding[];
  } | null;
  /** Veredicto dinámico replicado por hallazgo de Resultado 2 priority */
  agent4: DynamicVerdictedFinding[] | null;
  ranSuccessfully: boolean;
  errors: string[];
}

// ─── Final report (user-facing) ──────────────────────────────────────────────

export interface AnalysisReport {
  jobId: string;
  extensionId: string;
  extensionName?: string;
  extensionVersion?: string;
  extensionAuthor?: string;
  crxHash: string;
  analysisTimestamp: Date;
  analysisDuration: number;

  /** Agente 1 — propósito en lenguaje natural */
  agente1: Agent1Output | null;

  /** Dominios contactados (categoría priority) en formato URL */
  dominios_contactados_prioritarios: string[];

  /**
   * Resultados narrativos de análisis estático para hallazgos con veredicto positivo.
   * Forma: "En el <fileType> de la extensión, en la ruta <filePath>, línea <line>,
   *        descubrimos que <discoveryType>(<detail>), porque <razon>"
   */
  hallazgos_estaticos_positivos: string[];

  /**
   * Resultados narrativos de análisis dinámico para hallazgos con veredicto positivo
   * (sospechosa o maliciosa).
   * Forma: "En el <fileType> de la extensión, en la ruta <filePath>, línea <line>,
   *        descubrimos que <discoveryType>(<detail>), porque <accion_hecha>,
   *        por tanto <razon>"
   */
  hallazgos_dinamicos_positivos: string[];

  /** Optional structured copy of the verdicted findings for the frontend */
  estructura: {
    resultado1: VerdictedStaticFinding[];
    resultado2_priority: VerdictedDomainFinding[];
    resultado2_unknown: VerdictedDomainFinding[];
    resultado_dinamico: DynamicVerdictedFinding[];
  };
  /**
   * Step-by-step record of what the agent (Stagehand or IntelligentNavigator)
   * decided and executed per priority domain. Lets the frontend show a live
   * timeline and lets the user compare agents side by side.
   */
  navegacionDominios: DomainNavigationLog[];
}

export interface DomainNavigationLog {
  domain: string;
  url: string;
  navigatorUsed: 'stagehand' | 'intelligent_navigator';
  honeypotSessionUsed: boolean;
  agentSteps: AgentStep[];
  actionsPerformed: string[];
  error?: string;
}
