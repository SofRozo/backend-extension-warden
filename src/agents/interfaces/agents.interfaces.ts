// ─── Agent 1 — Holistic analyst ──────────────────────────────────────────────

/**
 * Agent 1 is now the ONLY LLM agent in the static phase. It analyses the whole
 * extension on its own — receives the manifest, the deterministic static
 * findings, the priority/unknown domain lists, and (when available) the
 * dynamic Stagehand observations + Agent 2 verdicts — and produces a verdict
 * with a written explanation.
 *
 * Agent 1 produces the HOLISTIC summary only: intent + verdict + explanation.
 * The per-finding narratives (`hallazgos_estaticos_positivos` and
 * `hallazgos_dinamicos_positivos`) are NOT Agent 1's job — they are produced
 * deterministically by the static-analysis layer and the report formatter so
 * the report is meaningful even when no LLM is configured.
 *
 * Field semantics:
 *  - proposito                                    → high-level intent (first
 *    sentence of the narrative report)
 *  - categoria                                    → Chrome Web Store category
 *    (propagated from preprocessed.cwsCategory; falls back to 'otro' for
 *    locally-uploaded extensions that don't have a CWS listing)
 *  - nivel_riesgo_inicial                         → preserved for the frontend
 *    Agent1Summary block
 *  - veredicto_global                             → holistic verdict
 *    (maliciosa | sospechosa | benigna)
 *  - explicacion                                  → 2-4 sentence paragraph the
 *    user reads in the drawer header
 *  - hallazgos_propios                            → items the agent discovered
 *    by reading the source code directly. These COMPLEMENT (do not replace)
 *    the deterministic static findings; the agent catches novel/contextual
 *    patterns the rules don't know about (encoded strings decoding to URLs,
 *    suspicious conditional logic, anti-analysis tricks, timer/date gates, etc.).
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
  respuestas_usuario?: Record<string, 'si' | 'no_detectado' | 'posible'>;
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
// DomainCategory now lives in common/interfaces/analysis.interfaces.ts because
// classification is deterministic and consumed by the static-analysis layer.
// We re-export here so existing imports keep working.

export type {
  DomainCategory,
  SandboxDomainObservation,
} from '../../common/interfaces/analysis.interfaces.js';
