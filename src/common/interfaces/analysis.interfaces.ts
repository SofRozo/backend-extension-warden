import { DetonationStrategy } from '../enums/risk-level.enum.js';
import type { Agent1Output } from '../../agents/interfaces/agents.interfaces.js';

/**
 * Sensitive-domain classification. Lives in analysis.interfaces.ts (not under
 * agents/) because classification is purely deterministic and is consumed by
 * the static-analysis layer; agents only read the resulting categories.
 */
export type DomainCategory =
  | 'propio_extension'
  | 'infraestructura_tecnica'
  | 'sensible_redes_sociales'
  | 'sensible_financiero'
  | 'sensible_identidad'
  | 'sensible_correo_productividad'
  | 'sensible_gubernamental'
  | 'sensible_llm'
  | 'sensible_data_broker'
  | 'desconocido';

// ─── File classification ─────────────────────────────────────────────────────

export type FileRole =
  | 'content_script'
  | 'background'
  | 'service_worker'
  | 'popup'
  | 'options_ui'
  | 'devtools'
  | 'sandbox'
  | 'override_page'
  | 'side_panel'
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

export type ResourceType =
  | 'javascript'
  | 'html'
  | 'json'
  | 'css'
  | 'archive'
  | 'other';

export interface ResourceInventoryEntry {
  path: string;
  type: ResourceType;
  sizeBytes: number;
  isMinified: boolean;
  lineCount: number;
}

export interface NestedArchiveFinding {
  path: string;
  line: number;
  detail: string;
}

export interface DependencyEdge {
  from: string;
  to: string;
  type:
    | 'manifest'
    | 'html_script'
    | 'static_import'
    | 'dynamic_import'
    | 'require'
    | 'worker'
    | 'scripting_executeScript'
    | 'script_injection';
  line: number;
}

export interface DependencyGraph {
  entries: string[];
  edges: DependencyEdge[];
  reachable: string[];
  orphanScripts: string[];
  unresolved: DependencyEdge[];
}

export interface ExtractedUrl {
  url: string;
  line: number;
  context: string;
  classification: UrlClassification;
}

export interface UrlClassification {
  protocol?: string;
  domain?: string;
  category:
    | 'trusted'
    | 'analytics'
    | 'unknown'
    | 'suspicious_tld'
    | 'raw_ip'
    | 'localhost'
    | 'non_https'
    | 'dynamic';
  reasons: string[];
}

export interface ProcessedFile {
  path: string;
  role: FileRole;
  isObfuscated: boolean;
  isMinified?: boolean;
  originalLineCount?: number;
  cleanCode?: string;
  urls: string[];
  extractedUrls?: ExtractedUrl[];
  /**
   * Every domain string seen in the source — includes URLs in `window.open`,
   * link attributes, comments, etc. Useful for inventory but NOT a sufficient
   * signal that the extension actually contacted the domain.
   */
  domains: ExtractedDomain[];
  /**
   * Subset of `domains`: only domains that appear as the argument of a
   * network sink (fetch / XHR / WebSocket / sendBeacon / chrome.*sendMessage).
   * These are the domains the extension actually contacts from its scripts.
   * Domains in `window.open`, `chrome.tabs.create`, `<a href>`, etc. are
   * deliberately excluded — those are navigation affordances, not contacts.
   * Populated by StaticAnalysisService when it runs the AST pass.
   */
  contactedDomains?: ExtractedDomain[];
  chromeApis: ExtractedChromeApi[];
  usesFetch: boolean;
  usesXHR: boolean;
  usesEval: boolean;
  usesDomManipulation: boolean;
  grepSignals?: string[];
  skippedAst?: boolean;
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
  optionalPermissions: string[];
  contentScripts: Array<{
    matches: string[];
    js: string[];
    css?: string[];
  }>;
  backgroundScripts: string[];
  serviceWorker?: string;
  popupUrl?: string;
  /** options_ui.page or options_page — settings page */
  optionsPage?: string;
  /** devtools_page — hidden page for DevTools panels */
  devtoolsPage?: string;
  /** side_panel.default_path — persistent side panel */
  sidePanelPath?: string;
  /** sandbox.pages — pages that can use eval/inline script */
  sandboxPages: string[];
  /** chrome_url_overrides — newtab / history / bookmarks replacement */
  chromeUrlOverrides: Record<string, string>;
  webAccessibleResources: unknown[];
  externallyConnectable?: Record<string, unknown>;
  declarativeNetRequestRules: string[];
  oauth2?: Record<string, unknown>;
  permissionRisk: Array<{
    permission: string;
    category: 'low' | 'medium' | 'high' | 'critical';
    weight: 1 | 2 | 5 | 10;
    hostSensitive: boolean;
    source: 'permissions' | 'optional_permissions' | 'host_permissions';
  }>;
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
  | 'permiso_chrome_manifest_riesgoso'
  | 'uso_api_chrome'
  | 'funcion_javascript_riesgosa'
  | 'flujo_datos_a_red'
  | 'codigo_ofuscado'
  | 'archivo_minificado'
  | 'archivo_huerfano'
  | 'archivo_anidado'
  | 'dependencia_no_resuelta'
  | 'script_remoto_mv3'
  | 'listener_teclado'
  | 'inyeccion_dom'
  | 'lectura_cookies'
  | 'lectura_storage_navegador'
  | 'interceptacion_api'
  | 'suplantacion_api_navegador'
  | 'correlacion_riesgo'
  | 'grep_signal_large_file';

export interface PreprocessingFinding {
  fileType: FileRole;
  filePath: string;
  discoveryType: StaticDiscoveryType;
  /** Concrete subject — e.g. "chrome.cookies.getAll", "eval", "innerHTML", "keydown", "cookies" */
  detail: string;
  line: number;
  /** Optional code snippet to help the agent reason */
  codeSnippet?: string;
  severity?: 'low' | 'medium' | 'high' | 'critical';
  category?: string;
  why?: string;
  confidence?: number;
  scoreImpact?: number;
}

// ─── Resultado 2 — URL/domain findings ───────────────────────────────────────

export type DomainDiscoveryType = 'url_en_codigo' | 'host_permission_manifest';

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
  resources: ResourceInventoryEntry[];
  nestedArchives: NestedArchiveFinding[];
  dependencyGraph: DependencyGraph;
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
  riskScore?: {
    score: number;
    level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    reasons: string[];
  };
  /** Category from Chrome Web Store (best-effort scrape, null if unavailable) */
  cwsCategory?: string | null;
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
 * navigator (Stagehand or IntelligentNavigator) before Agent 2 verdicts them.
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
export type DynamicVerdict =
  | 'maliciosa'
  | 'sospechosa'
  | 'benigna'
  | 'inaccesible';

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

/**
 * Output of the agent pipeline after the refactor that dropped the
 * SAST-per-finding and domain-abuse-per-finding agents. The static-analysis
 * layer (deterministic) now owns resultado1/resultado2; agents only contribute
 * the holistic narrative (Agent 1) and the dynamic per-domain verdict
 * (Agent 2 — originally numbered "Agent 4" before the others were removed).
 */
export interface AgentAnalysisResult {
  agent1: Agent1Output | null;
  /** Per-priority-domain dynamic verdict produced by Agent 2 from Stagehand observations. */
  agent2: DynamicVerdictedFinding[] | null;
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

  /** Resumen orientado a usuario final: capacidades y riesgos importantes. */
  resumen_usuario: UserRiskSummaryItem[];

  /** Veredicto final legible derivado del resumen de usuario. */
  veredicto_usuario: UserFacingVerdict;

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
  respuestas_usuario: Record<string, 'si' | 'no_detectado' | 'posible'> | null;
  puntuacion_riesgo?: {
    score: number;
    level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    reasons: string[];
  };
}

export type UserRiskSummaryId =
  | 'acceso_general_navegador'
  | 'modificacion_paginas'
  | 'lectura_informacion'
  | 'captura_credenciales'
  | 'keylogging'
  | 'seguimiento_privacidad'
  | 'manipulacion_trafico'
  | 'acceso_historial'
  | 'descargas_archivos'
  | 'ofuscacion_transparencia'
  | 'abuso_management'
  | 'mineria_recursos'
  | 'fingerprinting_severo';

export type UserRiskStatus =
  | 'no_detectado'
  | 'capacidad'
  | 'sospechoso'
  | 'critico';

/** One code-level finding attached to a category card. */
export interface HallazgoCodigo {
  filePath: string;
  line: number;
  fileType: string;
  texto: string;
}

export interface UserRiskSummaryItem {
  id: UserRiskSummaryId;
  titulo: string;
  estado: UserRiskStatus;
  resumen: string;
  evidencias: string[];
  /** IDs de reglas internas que explican por qué se marcó la categoría. */
  reglas_activadas?: string[];
  preguntas_responde: string[];
  /** Raw code findings (file + line) that belong to this category. */
  hallazgos_codigo?: HallazgoCodigo[];
}

export interface UserFacingVerdict {
  nivel: 'bajo' | 'medio' | 'alto' | 'critico';
  veredicto: 'benigna' | 'sospechosa' | 'maliciosa';
  resumen: string;
  razones: string[];
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
