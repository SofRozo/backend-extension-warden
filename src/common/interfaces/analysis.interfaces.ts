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

export interface GrepSignal {
  label: string;
  line: number;
  snippet: string;
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
  grepSignals?: GrepSignal[];
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
  | 'navegacion_externa_sensible'
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

// ─── Entity summary for Agent 1 ──────────────────────────────────────────────

/**
 * One row in the grouped entity summary passed to Agent 1.
 * Collapses all regional/subdomain variants of the same brand into a single
 * entry so the LLM reasons about "Amazon (22 subdomains)" rather than a flat
 * list of 22 nearly-identical hostnames.
 */
export interface DetectedEntity {
  /** Brand name, e.g. "Amazon", "Meta", "10xProfit" */
  entidad: string;
  /** Semantic category, e.g. "e-commerce", "lead_generation_third_party" */
  categoria: string;
  /** Number of distinct subdomains / domains seen for this entity */
  cantidad_subdominios: number;
  /** How the entity was encountered: host_permissions, content_scripts, url_en_codigo, dom_href_injection */
  metodos_uso: string[];
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
  /**
   * Grouped entity summary for Agent 1. Collapses regional/subdomain variants
   * of the same brand (e.g. all amazon.* TLDs) into one entry so the LLM
   * reasons about entities, not individual hostnames.
   */
  entidades_detectadas?: DetectedEntity[];
}

// ─── Verdicted findings ───────────────────────────────────────────────────────

export type VerdictPositive = 'positivo' | 'falso_positivo';

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

// ─── Combined agent results ───────────────────────────────────────────────────

export interface AgentAnalysisResult {
  agent1: Agent1Output | null;
  ranSuccessfully: boolean;
  errors: string[];
}

// ─── Unused permissions ──────────────────────────────────────────────────────

export interface PermisNoUsado {
  /** The Chrome API permission name, e.g. "cookies", "history", "management" */
  permission: string;
  /** Risk category derived from the preprocessor weight table */
  categoria: 'critical' | 'high' | 'medium' | 'low';
  /** Human-readable explanation of what this permission grants */
  descripcion: string;
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

  /** Resumen orientado a usuario final: capacidades y riesgos importantes. */
  resumen_usuario: UserRiskSummaryItem[];

  /** Veredicto final legible derivado del resumen de usuario. */
  veredicto_usuario: UserFacingVerdict;

  /** Narrativas de hallazgos estáticos con veredicto positivo. */
  hallazgos_estaticos_positivos: string[];

  /**
   * Permissions declared in the manifest but never observed in reachable code.
   * Expands the attack surface: a future update could weaponise them without
   * requesting new permissions (which Chrome highlights to the user).
   */
  permisos_no_usados: PermisNoUsado[];

  /** Structured copy of the verdicted findings for the frontend */
  estructura: {
    resultado1: VerdictedStaticFinding[];
    resultado2_priority: VerdictedDomainFinding[];
    resultado2_unknown: VerdictedDomainFinding[];
  };

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
  codeSnippet?: string;
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

export interface ThreatIntelResult {
  domain: string;
  provider: string;
  isMalicious: boolean;
  score: number;
  categories: string[];
  details: Record<string, unknown>;
  queriedAt: Date;
}

export interface UserFacingVerdict {
  nivel: 'bajo' | 'medio' | 'alto' | 'critico';
  veredicto: 'benigna' | 'sospechosa' | 'maliciosa';
  resumen: string;
  razones: string[];
}
