import { Injectable } from '@nestjs/common';
import { LlmClientService } from '../llm/llm-client.service.js';
import type { Agent4Output } from '../interfaces/agents.interfaces.js';
import type { SandboxDomainObservation } from '../../common/interfaces/analysis.interfaces.js';

@Injectable()
export class Agent4DynamicService {
  constructor(private readonly llm: LlmClientService) {}

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

Responde en JSON:
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
  "resumen": "string"
}
`;

    return (await this.llm.callLLM(prompt, jobId)) as Agent4Output;
  }
}
