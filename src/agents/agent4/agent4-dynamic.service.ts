import { Injectable } from '@nestjs/common';
import { LlmClientService } from '../llm/llm-client.service.js';
import { StructuredLogger } from '../../common/logger/logger.service.js';
import type {
  DomainFinding,
  DynamicVerdictedFinding,
  DynamicVerdict,
  SandboxDomainObservation,
} from '../../common/interfaces/analysis.interfaces.js';

const VALID_VERDICTS: DynamicVerdict[] = [
  'maliciosa',
  'sospechosa',
  'benigna',
  'inaccesible',
];

interface DomainVerdict {
  domain: string;
  veredicto: DynamicVerdict;
  accion_hecha: string;
  razon: string;
}

const PROMPT = `Eres un experto en comportamiento dinámico de extensiones de navegador.

Recibiste las observaciones del agente Stagehand/Playwright que navegó cada dominio prioritario.
Para CADA dominio decide:
- "veredicto": "maliciosa" si la extensión hizo algo claramente abusivo (exfiltración, keylogging,
  inyección no esperada); "sospechosa" si hay señales preocupantes pero no concluyentes;
  "benigna" si el comportamiento observado es consistente con el propósito declarado;
  "inaccesible" si la página no cargó o no se pudo interactuar.
- "accion_hecha": resumen breve (1 línea) de QUÉ hizo el navegador (clicks, escribió credenciales,
  detectó inyecciones de la extensión).
- "razon": 1-2 oraciones explicando el veredicto.

PROPÓSITO DECLARADO: {proposito}

OBSERVACIONES POR DOMINIO:
{observaciones}

Responde EXACTAMENTE con JSON (sin texto adicional):
{
  "dominios": [
    {
      "domain": "ejemplo.com",
      "veredicto": "maliciosa|sospechosa|benigna|inaccesible",
      "accion_hecha": "...",
      "razon": "..."
    }
  ]
}

DEBES devolver una entrada por cada dominio observado.`;

@Injectable()
export class Agent4DynamicService {
  constructor(
    private readonly llm: LlmClientService,
    private readonly logger: StructuredLogger,
  ) {}

  /**
   * Produces per-domain verdicts and replicates them onto each priority finding
   * whose domain matches. The result has one DynamicVerdictedFinding for every
   * priority finding (i.e. the same shape as resultado2_priority).
   */
  async analyze(
    proposito: string,
    priorityFindings: DomainFinding[],
    observations: SandboxDomainObservation[],
    jobId: string,
  ): Promise<DynamicVerdictedFinding[]> {
    if (priorityFindings.length === 0) return [];

    // Build a default verdict per priority domain (covers the "no observation"
    // case so every finding still gets a verdicted entry).
    const verdictByDomain = new Map<string, DomainVerdict>();
    for (const f of priorityFindings) {
      verdictByDomain.set(f.domain, {
        domain: f.domain,
        veredicto: 'inaccesible',
        accion_hecha: 'no se navegó este dominio',
        razon: 'Sin observaciones del navegador para este dominio',
      });
    }

    if (observations.length > 0) {
      const llmVerdicts = await this.runLlm(proposito, observations, jobId);
      for (const v of llmVerdicts) {
        verdictByDomain.set(v.domain.toLowerCase(), v);
      }
      // Fallback for observations without an LLM verdict
      for (const obs of observations) {
        const key = obs.domain.toLowerCase();
        if (!verdictByDomain.has(key)) continue;
        const cur = verdictByDomain.get(key)!;
        if (cur.veredicto === 'inaccesible') {
          verdictByDomain.set(key, this.heuristicVerdict(obs));
        }
      }
    }

    return priorityFindings.map((f) => {
      const v =
        verdictByDomain.get(f.domain.toLowerCase()) ??
        verdictByDomain.get(f.domain) ?? {
          domain: f.domain,
          veredicto: 'inaccesible' as DynamicVerdict,
          accion_hecha: 'no observado',
          razon: 'Sin información dinámica',
        };
      return {
        ...f,
        veredicto: v.veredicto,
        accion_hecha: v.accion_hecha,
        razon: v.razon,
      };
    });
  }

  // ─── LLM ──────────────────────────────────────────────────────────────────

  private async runLlm(
    proposito: string,
    observations: SandboxDomainObservation[],
    jobId: string,
  ): Promise<DomainVerdict[]> {
    const obsText = observations
      .map(
        (o) =>
          `### ${o.domain}\n` +
          `  url: ${o.url}\n` +
          `  honeypotSession: ${o.honeypotSessionUsed}\n` +
          `  requestsToThisDomain: ${o.requestsToThisDomain}\n` +
          `  domModificationsDetected: ${o.domModificationsDetected}\n` +
          `  credentialsSubmitted: ${o.credentialsSubmitted}\n` +
          `  actionsPerformed: ${(o.actionsPerformed ?? []).join(' | ')}\n` +
          `  observations:\n` +
          (o.observations ?? []).map((x) => `    - ${x}`).join('\n') +
          (o.error ? `\n  error: ${o.error}` : ''),
      )
      .join('\n\n');

    const prompt = PROMPT.replace('{proposito}', proposito).replace(
      '{observaciones}',
      obsText,
    );

    let raw: unknown;
    try {
      raw = await this.llm.callLLM(prompt, jobId);
    } catch (err) {
      this.logger.logWithJob(
        jobId,
        'warn',
        `Agent 4 LLM call failed: ${err instanceof Error ? err.message : String(err)}`,
        'Agent4DynamicService',
      );
      return observations.map((o) => this.heuristicVerdict(o));
    }

    const r = raw as { dominios?: Array<Record<string, unknown>> };
    const verdicts: DomainVerdict[] = [];
    if (Array.isArray(r?.dominios)) {
      for (const item of r.dominios) {
        const domain = String(item.domain ?? '').toLowerCase();
        if (!domain) continue;
        const v = String(item.veredicto ?? 'sospechosa') as DynamicVerdict;
        verdicts.push({
          domain,
          veredicto: VALID_VERDICTS.includes(v) ? v : 'sospechosa',
          accion_hecha: String(item.accion_hecha ?? ''),
          razon: String(item.razon ?? ''),
        });
      }
    }

    if (verdicts.length === 0) {
      this.logger.logWithJob(
        jobId,
        'warn',
        'Agent 4 returned no domain verdicts — using heuristic fallback',
        'Agent4DynamicService',
      );
      return observations.map((o) => this.heuristicVerdict(o));
    }

    return verdicts;
  }

  /**
   * Conservative fallback when the LLM didn't deliver a usable verdict.
   * "sospechosa" if we observed the extension modifying DOM or credentials
   * being submitted, "benigna" otherwise.
   */
  private heuristicVerdict(obs: SandboxDomainObservation): DomainVerdict {
    if (obs.error) {
      return {
        domain: obs.domain.toLowerCase(),
        veredicto: 'inaccesible',
        accion_hecha: 'no se pudo cargar la página',
        razon: obs.error,
      };
    }
    const suspicious =
      obs.domModificationsDetected ||
      obs.credentialsSubmitted ||
      obs.requestsToThisDomain > 5;
    return {
      domain: obs.domain.toLowerCase(),
      veredicto: suspicious ? 'sospechosa' : 'benigna',
      accion_hecha: (obs.actionsPerformed ?? []).slice(0, 3).join(' | '),
      razon: suspicious
        ? 'La extensión modificó el DOM o se enviaron credenciales en este dominio'
        : 'No se observó comportamiento abusivo durante la navegación',
    };
  }
}
