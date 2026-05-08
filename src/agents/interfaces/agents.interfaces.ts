import type {
  FileRole,
  SandboxDomainObservation,
} from '../../common/interfaces/analysis.interfaces.js';

export type { SandboxDomainObservation };

// ─── Agent 1 — Intention & Purpose ───────────────────────────────────────────

export interface Agent1Output {
  proposito: string;
  categoria: string;
  acciones_esperadas: string[];
  acciones_NO_esperadas: string[];
  senales_alarma_manifest: string[];
  nivel_riesgo_inicial: 'bajo' | 'medio' | 'alto' | 'critico';
  razon_nivel_riesgo: string;
}

// ─── Agent 2 — SAST + Domain Classification ──────────────────────────────────

export type DomainCategory =
  | 'propio_extension'
  | 'infraestructura_tecnica'
  | 'sensible_redes_sociales'
  | 'sensible_financiero'
  | 'sensible_identidad'
  | 'sensible_correo_productividad'
  | 'sensible_gubernamental'
  | 'desconocido';

export interface CategorizedDomain {
  domain: string;
  category: DomainCategory;
  reasoning: string;
  goesToPlaywright: boolean;
  playwrightPriority?: number; // 1 = highest (financiero), 5 = lowest (desconocido)
}

export interface Agent2Finding {
  archivo: string;
  rol: FileRole;
  descripcion: string;
  severidad: 'critica' | 'alta' | 'media' | 'baja' | 'info';
  tipo: string;
  evidencia?: string;
}

export interface Agent2Output {
  hallazgos: Agent2Finding[];
  dominios_categorizados: CategorizedDomain[];
  dominios_para_playwright: CategorizedDomain[];
  hay_ofuscacion: boolean;
  archivos_ofuscados: string[];
  apis_chrome_resumen: string;
  flujos_datos_sospechosos: string[];
}

// ─── Agent 3 — Permission Abuse Evaluation ───────────────────────────────────

export interface Agent3Evaluation {
  hallazgo: string;
  archivo: string;
  es_abuso: boolean;
  confianza: 'alta' | 'media' | 'baja';
  razonamiento: string;
  severidad_final: 'critica' | 'alta' | 'media' | 'baja' | 'falso_positivo';
}

export interface Agent3PermissionAbuse {
  permiso: string;
  como_se_abusa: string;
  evidencia: string;
}

export interface Agent3Output {
  evaluaciones: Agent3Evaluation[];
  permisos_abusados: Agent3PermissionAbuse[];
  veredicto_preliminar: 'benigna' | 'sospechosa' | 'maliciosa';
  razon_veredicto: string;
}

// ─── Agent 4 — Dynamic Log Analysis ──────────────────────────────────────────

export interface Agent4ContactDetail {
  dominio: string;
  tipo_peticion: string;
  parece_exfiltracion: boolean;
  razonamiento: string;
}

export interface Agent4Output {
  contacto_dominios_sensibles: boolean;
  detalle_contactos: Agent4ContactDetail[];
  modificaciones_dom_sospechosas: string[];
  comportamiento_inesperado: string[];
  confirma_hallazgos_estaticos: boolean;
  nuevos_hallazgos: string[];
  veredicto_dinamico: 'benigna' | 'sospechosa' | 'maliciosa';
  resumen: string;
}

// ─── Combined result returned by AgentsOrchestratorService ───────────────────

export interface AgentAnalysisResult {
  agent1: Agent1Output | null;
  agent2: Agent2Output | null;
  agent3: Agent3Output | null;
  agent4?: Agent4Output | null;
  ranSuccessfully: boolean;
  errors: string[];
}
