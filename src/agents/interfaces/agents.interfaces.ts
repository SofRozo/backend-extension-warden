// ─── Agent 1 — Holistic analyst ──────────────────────────────────────────────

/**
 * Agent 1 is the sole LLM agent. Receives manifest, deterministic static
 * findings, domain lists, and entity summary; produces a holistic verdict
 * with a written explanation. Per-finding narratives are produced
 * deterministically by the report formatter.
 */
export interface Agent1Output {
  proposito: string;
  categoria: string;
  nivel_riesgo_inicial: 'bajo' | 'medio' | 'alto' | 'critico';
  veredicto_global: 'maliciosa' | 'sospechosa' | 'benigna';
  explicacion: string;
  /** Whether the extension violates the Principle of Least Privilege (PoLP).
   *  detectada = true means at least one mismatch was found between declared
   *  permissions and what the extension actually needs for its purpose. */
  violacion_minimo_privilegio?: {
    detectada: boolean;
    razones: string[];
  };
  hallazgos_propios?: AgentFinding[];
  respuestas_usuario?: Record<string, { valor: 'si' | 'no_detectado' | 'posible'; razon: string }>;
}

/**
 * A finding the LLM agent identified by reading code directly. Separate from
 * the deterministic PreprocessingFinding so the UI can label them as
 * "additional review by the agent" and avoid double-counting against the rules.
 */
export interface AgentFinding {
  archivo: string;
  linea?: number;
  /** Free-form short label, e.g. "exfiltración", "obfuscación", "anti-análisis". */
  tipo: string;
  descripcion: string;
  severidad: 'bajo' | 'medio' | 'alto' | 'critico';
  /** Optional code excerpt the agent referenced. */
  snippet?: string;
}

// ─── Re-exports ──────────────────────────────────────────────────────────────

export type { DomainCategory } from '../../common/interfaces/analysis.interfaces.js';
