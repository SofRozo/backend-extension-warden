import { Injectable } from '@nestjs/common';
import { LlmClientService } from '../llm/llm-client.service.js';
import { StructuredLogger } from '../../common/logger/logger.service.js';
import type { ManifestInfo } from '../../common/interfaces/analysis.interfaces.js';
import type {
  Agent1Output,
  Agent2Output,
  Agent3Output,
  Agent3Evaluation,
  Agent3PermissionAbuse,
} from '../interfaces/agents.interfaces.js';

// ─── Prompt ───────────────────────────────────────────────────────────────────

const PROMPT = `Eres un auditor de seguridad especializado en extensiones de navegador.

Tu trabajo es determinar si cada hallazgo del análisis estático representa un
ABUSO DE PERMISOS o un COMPORTAMIENTO LEGÍTIMO, considerando el propósito de la extensión.

PROPÓSITO Y CONTEXTO (Agente 1):
{output_agente_1}

HALLAZGOS DEL ANÁLISIS DE CÓDIGO (Agente 2):
{output_agente_2}

PERMISOS DECLARADOS EN EL MANIFEST:
{permisos}

DOMINIOS SENSIBLES IDENTIFICADOS:
{dominios_sensibles}

Para cada hallazgo razona así:
1. ¿Este comportamiento es necesario para el propósito declarado de la extensión?
2. ¿El archivo que lo hace tiene el rol correcto?
   (content_script haciendo cosas que solo debería hacer el background = sospechoso)
3. ¿Los datos accedidos fluyen hacia dominios externos? ¿Cuáles?
4. ¿Existe una explicación benigna razonable?

EJEMPLOS DE RAZONAMIENTO:
- html2canvas en extensión de mascota virtual → LEGÍTIMO (captura el estado del perrito en la página)
- html2canvas capturando página de login → ABUSO (captura credenciales visibles en la pantalla)
- keydown listener en popup → LEGÍTIMO (UX del popup, no captura teclas del sitio)
- keydown listener en content_script enviando datos a servidor → ABUSO (keylogger)
- fetch() a instagram.com desde extensión de redes sociales → INVESTIGAR (posible legítimo)
- fetch() a instagram.com desde extensión de mascota virtual → ABUSO (sin justificación)
- Código ofuscado en extensión funcional → SEÑAL DE ALERTA independiente del propósito

Si no hay hallazgos o todos son legítimos, reporta evaluaciones vacías y veredicto "benigna".

Responde en JSON exactamente así (sin texto adicional):
{
  "evaluaciones": [
    {
      "hallazgo": "descripción del hallazgo del Agente 2",
      "archivo": "ruta/archivo.js",
      "es_abuso": true,
      "confianza": "alta|media|baja",
      "razonamiento": "explicación detallada de por qué es o no un abuso",
      "severidad_final": "critica|alta|media|baja|falso_positivo"
    }
  ],
  "permisos_abusados": [
    {
      "permiso": "nombre del permiso de Chrome",
      "como_se_abusa": "descripción de cómo se usa indebidamente",
      "evidencia": "archivo:descripción específica"
    }
  ],
  "veredicto_preliminar": "benigna|sospechosa|maliciosa",
  "razon_veredicto": "explicación del veredicto en 1-2 oraciones"
}`;

// ─── Validation helpers ───────────────────────────────────────────────────────

const VALID_VERDICTS = new Set(['benigna', 'sospechosa', 'maliciosa']);
const VALID_SEVERITIES = new Set([
  'critica',
  'alta',
  'media',
  'baja',
  'falso_positivo',
]);
const VALID_CONFIDENCE = new Set(['alta', 'media', 'baja']);

@Injectable()
export class Agent3AbuseService {
  constructor(
    private readonly llm: LlmClientService,
    private readonly logger: StructuredLogger,
  ) {}

  async analyze(
    agent1: Agent1Output,
    agent2: Agent2Output,
    manifest: ManifestInfo,
    jobId: string,
  ): Promise<Agent3Output> {
    if (agent2.hallazgos.length === 0) {
      this.logger.logWithJob(
        jobId,
        'info',
        'Agent 3 — no findings from Agent 2, returning clean verdict',
        'Agent3AbuseService',
      );
      return {
        evaluaciones: [],
        permisos_abusados: [],
        veredicto_preliminar: 'benigna',
        razon_veredicto:
          'El Agente 2 no identificó hallazgos de comportamiento sospechoso.',
      };
    }

    // Build the context sections
    const outputAgente1 = JSON.stringify(
      {
        proposito: agent1.proposito,
        categoria: agent1.categoria,
        acciones_esperadas: agent1.acciones_esperadas,
        acciones_NO_esperadas: agent1.acciones_NO_esperadas,
        senales_alarma_manifest: agent1.senales_alarma_manifest,
        nivel_riesgo_inicial: agent1.nivel_riesgo_inicial,
      },
      null,
      2,
    );

    // Only pass hallazgos + obfuscation info to Agent 3 — it doesn't need the full domain list
    const outputAgente2 = JSON.stringify(
      {
        hallazgos: agent2.hallazgos,
        hay_ofuscacion: agent2.hay_ofuscacion,
        archivos_ofuscados: agent2.archivos_ofuscados,
        flujos_datos_sospechosos: agent2.flujos_datos_sospechosos,
        apis_chrome_resumen: agent2.apis_chrome_resumen,
      },
      null,
      2,
    );

    const permisos = JSON.stringify(
      {
        api_permissions: manifest.apiPermissions,
        host_permissions: manifest.hostPermissions,
      },
      null,
      2,
    );

    // Only show sensitive domains that go to Playwright — these are the ones
    // that matter for evaluating if data is being sent to the wrong place
    const dominiosSensibles =
      agent2.dominios_para_playwright.length > 0
        ? agent2.dominios_para_playwright
            .map((d) => `  - ${d.domain} [${d.category}]: ${d.reasoning}`)
            .join('\n')
        : '  (ninguno identificado)';

    const prompt = PROMPT.replace('{output_agente_1}', outputAgente1)
      .replace('{output_agente_2}', outputAgente2)
      .replace('{permisos}', permisos)
      .replace('{dominios_sensibles}', dominiosSensibles);

    this.logger.logWithJob(
      jobId,
      'info',
      `Agent 3 — evaluating ${agent2.hallazgos.length} findings`,
      'Agent3AbuseService',
    );

    const raw = await this.llm.callLLM(prompt, jobId);
    return this.validate(raw, jobId);
  }

  private validate(raw: unknown, jobId: string): Agent3Output {
    const r = raw as Record<string, unknown>;

    if (!r || typeof r !== 'object') {
      throw new Error('Agent 3 returned non-object response');
    }

    const evaluaciones: Agent3Evaluation[] = [];
    if (Array.isArray(r.evaluaciones)) {
      for (const item of r.evaluaciones) {
        const e = item as Partial<Agent3Evaluation>;
        if (!e.hallazgo) continue;

        evaluaciones.push({
          hallazgo: String(e.hallazgo),
          archivo: String(e.archivo ?? '(desconocido)'),
          es_abuso: Boolean(e.es_abuso),
          confianza: VALID_CONFIDENCE.has(e.confianza ?? '')
            ? (e.confianza as Agent3Evaluation['confianza'])
            : 'media',
          razonamiento: String(e.razonamiento ?? ''),
          severidad_final: VALID_SEVERITIES.has(e.severidad_final ?? '')
            ? (e.severidad_final as Agent3Evaluation['severidad_final'])
            : 'media',
        });
      }
    }

    const permisos_abusados: Agent3PermissionAbuse[] = [];
    if (Array.isArray(r.permisos_abusados)) {
      for (const item of r.permisos_abusados) {
        const p = item as Partial<Agent3PermissionAbuse>;
        if (!p.permiso) continue;
        permisos_abusados.push({
          permiso: String(p.permiso),
          como_se_abusa: String(p.como_se_abusa ?? ''),
          evidencia: String(p.evidencia ?? ''),
        });
      }
    }

    const veredicto = String(r.veredicto_preliminar ?? 'sospechosa');
    if (!VALID_VERDICTS.has(veredicto)) {
      this.logger.logWithJob(
        jobId,
        'warn',
        `Agent 3 returned unexpected veredicto="${veredicto}", defaulting to "sospechosa"`,
        'Agent3AbuseService',
      );
    }

    return {
      evaluaciones,
      permisos_abusados,
      veredicto_preliminar: VALID_VERDICTS.has(veredicto)
        ? (veredicto as Agent3Output['veredicto_preliminar'])
        : 'sospechosa',
      razon_veredicto: String(r.razon_veredicto ?? ''),
    };
  }
}
