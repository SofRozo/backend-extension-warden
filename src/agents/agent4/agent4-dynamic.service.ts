import { Injectable } from '@nestjs/common';
import { LlmClientService } from '../llm/llm-client.service.js';
import { StructuredLogger } from '../../common/logger/logger.service.js';
import type { Agent4Output, Agent4ContactDetail } from '../interfaces/agents.interfaces.js';
import type { SandboxDomainObservation } from '../../common/interfaces/analysis.interfaces.js';

const VALID_VERDICTS = new Set(['benigna', 'sospechosa', 'maliciosa']);

@Injectable()
export class Agent4DynamicService {
  constructor(
    private readonly llm: LlmClientService,
    private readonly logger: StructuredLogger,
  ) {}

  async analyze(
    proposito: string,
    veredictoEstatico: string,
    observations: SandboxDomainObservation[],
    jobId: string,
  ): Promise<Agent4Output> {
    const prompt = `
Eres un experto en comportamiento dinámico de extensiones de navegador.

PROPÓSITO DE LA EXTENSIÓN: ${proposito}
VEREDICTO ESTÁTICO: ${veredictoEstatico}

OBSERVACIONES DEL AGENTE (STAGEHAND) EN EL NAVEGADOR:
${JSON.stringify(observations, null, 2)}

Basándote en las observaciones del agente, determina:
1. ¿Se confirmó alguno de los hallazgos del análisis estático?
2. ¿Se detectó exfiltración de datos (credenciales, contenido de página, cookies)?
3. ¿La extensión modificó páginas sensibles de formas no esperadas?
4. ¿Qué comportamiento nuevo se descubrió que el análisis estático no vio?

Responde en JSON exactamente así (sin texto adicional):
{
  "contacto_dominios_sensibles": boolean,
  "detalle_contactos": [
    {
      "dominio": "string",
      "tipo_peticion": "string",
      "parece_exfiltracion": boolean,
      "razonamiento": "string"
    }
  ],
  "modificaciones_dom_sospechosas": ["string"],
  "comportamiento_inesperado": ["string"],
  "confirma_hallazgos_estaticos": boolean,
  "nuevos_hallazgos": ["string"],
  "veredicto_dinamico": "benigna|sospechosa|maliciosa",
  "resumen": "2-3 oraciones explicando qué encontró el agente"
}
`;

    this.logger.logWithJob(
      jobId,
      'info',
      `Agent 4 — analyzing ${observations.length} domain observation(s)`,
      'Agent4DynamicService',
    );

    const raw = await this.llm.callLLM(prompt, jobId);
    return this.validate(raw, jobId);
  }

  private validate(raw: unknown, jobId: string): Agent4Output {
    const r = raw as Record<string, unknown>;

    if (!r || typeof r !== 'object') {
      throw new Error('Agent 4 returned non-object response');
    }

    const detalle_contactos: Agent4ContactDetail[] = [];
    if (Array.isArray(r.detalle_contactos)) {
      for (const item of r.detalle_contactos) {
        const c = item as Partial<Agent4ContactDetail>;
        if (!c.dominio) continue;
        detalle_contactos.push({
          dominio: String(c.dominio),
          tipo_peticion: String(c.tipo_peticion ?? 'GET'),
          parece_exfiltracion: Boolean(c.parece_exfiltracion),
          razonamiento: String(c.razonamiento ?? ''),
        });
      }
    }

    const veredicto = String(r.veredicto_dinamico ?? 'sospechosa');
    if (!VALID_VERDICTS.has(veredicto)) {
      this.logger.logWithJob(
        jobId,
        'warn',
        `Agent 4 returned unexpected veredicto_dinamico="${veredicto}", defaulting to "sospechosa"`,
        'Agent4DynamicService',
      );
    }

    return {
      contacto_dominios_sensibles: Boolean(r.contacto_dominios_sensibles),
      detalle_contactos,
      modificaciones_dom_sospechosas: toStringArray(r.modificaciones_dom_sospechosas),
      comportamiento_inesperado: toStringArray(r.comportamiento_inesperado),
      confirma_hallazgos_estaticos: Boolean(r.confirma_hallazgos_estaticos),
      nuevos_hallazgos: toStringArray(r.nuevos_hallazgos),
      veredicto_dinamico: VALID_VERDICTS.has(veredicto)
        ? veredicto as Agent4Output['veredicto_dinamico']
        : 'sospechosa',
      resumen: String(r.resumen ?? ''),
    };
  }
}

function toStringArray(v: unknown): string[] {
  if (!Array.isArray(v)) return [];
  return v.map(String);
}
