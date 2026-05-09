import { Injectable } from '@nestjs/common';
import { LlmClientService } from '../llm/llm-client.service.js';
import { ThreatIntelService } from '../../threat-intel/threat-intel.service.js';
import { StructuredLogger } from '../../common/logger/logger.service.js';
import type {
  DomainFinding,
  VerdictedDomainFinding,
  VerdictPositive,
  ThreatIntelResult,
} from '../../common/interfaces/analysis.interfaces.js';
import type { Agent1Output } from '../interfaces/agents.interfaces.js';

const PROMPT = `Eres un auditor de seguridad evaluando los DOMINIOS contactados por una extensión de navegador.

PROPÓSITO DECLARADO (Agente 1):
{contexto_agente1}

DOMINIOS A EVALUAR — cada uno representa un descubrimiento individual con su archivo, ruta y línea.
Algunos vienen ya clasificados deterministicamente como prioritarios (financiero/identidad/llm/redes/correo/gob),
otros son desconocidos y se enriquecieron con threat intelligence.

LISTA:
{hallazgos}

Para CADA dominio decide:
- "veredicto": "positivo" si el contacto con ese dominio es REALMENTE preocupante para el propósito declarado
  (exfiltración a un sitio sin justificación, acceso a datos sensibles innecesarios, dominio malicioso
  según threat intel, etc.). "falso_positivo" si tiene una explicación benigna razonable
  (ej. extensión de redes sociales contactando instagram.com).
- "razon": 1-2 oraciones explicando por qué.

REGLAS:
- Dominio marcado como malicioso por threat intel → SIEMPRE positivo.
- Dominio que no tiene relación con el propósito declarado → positivo.
- Dominio prioritario que coincide con la categoría de la extensión → falso_positivo.

Responde EXACTAMENTE con un JSON con esta forma (sin texto adicional):
{
  "evaluaciones": [
    { "indice": 0, "veredicto": "positivo" | "falso_positivo", "razon": "..." }
  ]
}

DEBES devolver una entrada por cada hallazgo numerado en la lista, en el mismo orden.`;

const VALID_VERDICTS: VerdictPositive[] = ['positivo', 'falso_positivo'];

@Injectable()
export class Agent3AbuseService {
  constructor(
    private readonly llm: LlmClientService,
    private readonly threatIntel: ThreatIntelService,
    private readonly logger: StructuredLogger,
  ) {}

  async analyze(
    agent1: Agent1Output,
    priority: DomainFinding[],
    unknown: DomainFinding[],
    jobId: string,
  ): Promise<{
    priority: VerdictedDomainFinding[];
    unknown: VerdictedDomainFinding[];
  }> {
    if (priority.length === 0 && unknown.length === 0) {
      return { priority: [], unknown: [] };
    }

    // ── Threat-intel enrichment for unknown domains ───────────────────────────
    const uniqueUnknownDomains = [...new Set(unknown.map((u) => u.domain))];
    const tiByDomain = new Map<string, ThreatIntelResult[]>();
    if (uniqueUnknownDomains.length > 0) {
      try {
        const tiResults = await this.threatIntel.queryDomains(
          uniqueUnknownDomains,
          jobId,
        );
        for (const r of tiResults) {
          const list = tiByDomain.get(r.domain) ?? [];
          list.push(r);
          tiByDomain.set(r.domain, list);
        }
      } catch (err) {
        this.logger.logWithJob(
          jobId,
          'warn',
          `Threat intel enrichment failed: ${err instanceof Error ? err.message : String(err)}`,
          'Agent3AbuseService',
        );
      }
    }

    // ── Build single LLM payload covering BOTH lists with a global index ──────
    const all: Array<{ kind: 'priority' | 'unknown'; idx: number; finding: DomainFinding; tiSummary?: string }> =
      [
        ...priority.map((finding, idx) => ({
          kind: 'priority' as const,
          idx,
          finding,
        })),
        ...unknown.map((finding, idx) => ({
          kind: 'unknown' as const,
          idx,
          finding,
          tiSummary: this.summarizeThreatIntel(tiByDomain.get(finding.domain) ?? []),
        })),
      ];

    const contextoAgente1 = JSON.stringify(
      {
        proposito: agent1.proposito,
        categoria: agent1.categoria,
        acciones_esperadas: agent1.acciones_esperadas,
      },
      null,
      2,
    );

    const hallazgosTexto = all
      .map((entry, i) => {
        const f = entry.finding;
        return (
          `[${i}] kind=${entry.kind} | domain=${f.domain} | category=${f.category} | ` +
          `fileType=${f.fileType} | filePath=${f.filePath} | line=${f.line} | ` +
          `discoveryType=${f.discoveryType}` +
          (entry.tiSummary ? `\n    threatIntel: ${entry.tiSummary}` : '')
        );
      })
      .join('\n');

    const prompt = PROMPT.replace('{contexto_agente1}', contextoAgente1).replace(
      '{hallazgos}',
      hallazgosTexto,
    );

    this.logger.logWithJob(
      jobId,
      'info',
      `Agent 3 — evaluating ${priority.length} priority + ${unknown.length} unknown domain findings`,
      'Agent3AbuseService',
    );

    let raw: unknown;
    try {
      raw = await this.llm.callLLM(prompt, jobId);
    } catch (err) {
      this.logger.logWithJob(
        jobId,
        'warn',
        `Agent 3 LLM call failed: ${err instanceof Error ? err.message : String(err)}`,
        'Agent3AbuseService',
      );
      // Fail-open: priority domains are positive, unknowns inherit threat-intel signal
      return {
        priority: priority.map((f) => this.fallback(f, 'LLM no disponible — dominio prioritario marcado como positivo por defecto', 'positivo')),
        unknown: unknown.map((f) => {
          const ti = tiByDomain.get(f.domain) ?? [];
          const malicious = ti.some((t) => t.isMalicious);
          return this.fallback(
            f,
            malicious
              ? 'Threat intel marcó el dominio como malicioso (LLM no disponible)'
              : 'Sin información — LLM no disponible',
            malicious ? 'positivo' : 'falso_positivo',
            this.summarizeThreatIntel(ti),
          );
        }),
      };
    }

    return this.mergeVerdicts(all, raw, jobId);
  }

  // ─── Helpers ───────────────────────────────────────────────────────────────

  private mergeVerdicts(
    all: Array<{ kind: 'priority' | 'unknown'; idx: number; finding: DomainFinding; tiSummary?: string }>,
    raw: unknown,
    jobId: string,
  ): { priority: VerdictedDomainFinding[]; unknown: VerdictedDomainFinding[] } {
    const r = raw as { evaluaciones?: Array<Record<string, unknown>> };
    const byIndex = new Map<number, { veredicto: VerdictPositive; razon: string }>();

    if (Array.isArray(r?.evaluaciones)) {
      for (const e of r.evaluaciones) {
        const i =
          typeof e.indice === 'number'
            ? e.indice
            : Number.parseInt(String(e.indice ?? ''), 10);
        if (!Number.isInteger(i) || i < 0 || i >= all.length) continue;
        const veredicto = String(e.veredicto ?? 'positivo') as VerdictPositive;
        byIndex.set(i, {
          veredicto: VALID_VERDICTS.includes(veredicto) ? veredicto : 'positivo',
          razon: String(e.razon ?? ''),
        });
      }
    }

    if (byIndex.size !== all.length) {
      this.logger.logWithJob(
        jobId,
        'warn',
        `Agent 3 returned ${byIndex.size}/${all.length} verdicts; missing entries default to "positivo"`,
        'Agent3AbuseService',
      );
    }

    const priorityOut: VerdictedDomainFinding[] = [];
    const unknownOut: VerdictedDomainFinding[] = [];
    for (let i = 0; i < all.length; i++) {
      const entry = all[i];
      const v = byIndex.get(i) ?? {
        veredicto: 'positivo' as VerdictPositive,
        razon: 'Agente 3 no emitió veredicto explícito',
      };
      const out: VerdictedDomainFinding = {
        ...entry.finding,
        veredicto: v.veredicto,
        razon: v.razon,
        threatIntelSummary: entry.tiSummary,
      };
      if (entry.kind === 'priority') priorityOut.push(out);
      else unknownOut.push(out);
    }

    return { priority: priorityOut, unknown: unknownOut };
  }

  private fallback(
    f: DomainFinding,
    razon: string,
    veredicto: VerdictPositive,
    threatIntelSummary?: string,
  ): VerdictedDomainFinding {
    return { ...f, veredicto, razon, threatIntelSummary };
  }

  private summarizeThreatIntel(results: ThreatIntelResult[]): string {
    if (results.length === 0) return 'sin información de threat intel';
    const malicious = results.filter((r) => r.isMalicious);
    if (malicious.length > 0) {
      return `MALICIOSO según ${malicious.map((r) => r.provider).join(', ')}`;
    }
    const cats = [...new Set(results.flatMap((r) => r.categories ?? []))].slice(0, 4);
    return cats.length > 0
      ? `limpio — categorías: ${cats.join(', ')}`
      : 'limpio según threat intel';
  }
}
