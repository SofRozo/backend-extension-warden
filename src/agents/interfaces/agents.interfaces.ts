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

// ─── Domain categories ───────────────────────────────────────────────────────

export type DomainCategory =
  | 'propio_extension'
  | 'infraestructura_tecnica'
  | 'sensible_redes_sociales'
  | 'sensible_financiero'
  | 'sensible_identidad'
  | 'sensible_correo_productividad'
  | 'sensible_gubernamental'
  | 'sensible_llm'
  | 'desconocido';

/**
 * Backwards-compatible re-exports so the rest of the codebase keeps importing
 * SandboxDomainObservation from this module.
 */
export type { SandboxDomainObservation } from '../../common/interfaces/analysis.interfaces.js';
