import { Injectable } from '@nestjs/common';
import { LlmClientService } from '../llm/llm-client.service.js';
import { StructuredLogger } from '../../common/logger/logger.service.js';
import type { PreprocessorOutput } from '../../common/interfaces/analysis.interfaces.js';
import type { Agent1Output } from '../interfaces/agents.interfaces.js';

const PROMPT = `Eres un experto en seguridad de extensiones de navegador.

Se te proporciona información estructurada de una extensión de Chrome/Firefox.
Tu tarea es determinar:

1. PROPÓSITO DECLARADO: ¿Qué dice hacer la extensión según su nombre, descripción y manifest?
2. CATEGORÍA: elige una de (productividad / entretenimiento / seguridad / utilidad / red_social / compras / otro)
3. ACCIONES ESPERADAS: Dado el propósito, ¿qué comportamientos técnicos son normales y esperables?
   Ejemplos:
   - Una extensión de notas DEBE escribir en storage. NO debe leer el DOM de páginas bancarias.
   - Una mascota virtual DEBE modificar el DOM para mostrar la mascota. NO debe interceptar formularios de login.
   - Un gestor de contraseñas DEBE acceder a formularios. Eso es su función legítima.
4. SEÑALES DE ALARMA INICIALES: ¿Hay algo en el manifest o en los permisos que sea inconsistente con el propósito?

DATOS DE LA EXTENSIÓN:
{datos}

Responde en JSON con esta estructura exacta (sin texto adicional):
{
  "proposito": "descripción breve del propósito declarado",
  "categoria": "productividad|entretenimiento|seguridad|utilidad|red_social|compras|otro",
  "acciones_esperadas": ["...", "..."],
  "acciones_NO_esperadas": ["...", "..."],
  "senales_alarma_manifest": ["...", "..."],
  "nivel_riesgo_inicial": "bajo|medio|alto|critico",
  "razon_nivel_riesgo": "explicación breve"
}`;

const VALID_RISK_LEVELS = new Set(['bajo', 'medio', 'alto', 'critico']);

@Injectable()
export class Agent1IntentionService {
  constructor(
    private readonly llm: LlmClientService,
    private readonly logger: StructuredLogger,
  ) {}

  async analyze(preprocessed: PreprocessorOutput, jobId: string): Promise<Agent1Output> {
    const { manifest, files } = preprocessed;

    // Build file list — exclude libraries, show role and obfuscation flag
    const fileList = files
      .filter((f) => f.role !== 'library')
      .map((f) => `  - ${f.path} [${f.role}${f.isObfuscated ? ', OFUSCADO' : ''}]`)
      .join('\n');

    const datos = JSON.stringify(
      {
        nombre: manifest.name,
        descripcion: manifest.description ?? '(sin descripción)',
        manifest_version: manifest.manifestVersion,
        permisos_api: manifest.apiPermissions,
        host_permissions: manifest.hostPermissions,
        content_scripts_activos_en: manifest.contentScripts.flatMap((cs) => cs.matches),
        background: manifest.serviceWorker ?? manifest.backgroundScripts ?? null,
        popup: manifest.popupUrl ?? null,
        archivos_clasificados: `\n${fileList}`,
      },
      null,
      2,
    );

    const prompt = PROMPT.replace('{datos}', datos);

    this.logger.logWithJob(jobId, 'info', 'Agent 1 — analyzing intention', 'Agent1IntentionService');

    const raw = await this.llm.callLLM(prompt, jobId);
    return this.validate(raw, jobId);
  }

  private validate(raw: unknown, jobId: string): Agent1Output {
    const r = raw as Partial<Agent1Output>;

    if (!r || typeof r !== 'object') {
      throw new Error('Agent 1 returned non-object response');
    }
    if (!r.proposito) {
      throw new Error('Agent 1 response missing required field: proposito');
    }

    const nivel = r.nivel_riesgo_inicial ?? 'medio';
    if (!VALID_RISK_LEVELS.has(nivel)) {
      this.logger.logWithJob(
        jobId,
        'warn',
        `Agent 1 returned unexpected nivel_riesgo_inicial="${nivel}", defaulting to "medio"`,
        'Agent1IntentionService',
      );
    }

    return {
      proposito: String(r.proposito),
      categoria: String(r.categoria ?? 'otro'),
      acciones_esperadas: toStringArray(r.acciones_esperadas),
      acciones_NO_esperadas: toStringArray(r.acciones_NO_esperadas),
      senales_alarma_manifest: toStringArray(r.senales_alarma_manifest),
      nivel_riesgo_inicial: VALID_RISK_LEVELS.has(nivel) ? nivel as Agent1Output['nivel_riesgo_inicial'] : 'medio',
      razon_nivel_riesgo: String(r.razon_nivel_riesgo ?? ''),
    };
  }
}

function toStringArray(v: unknown): string[] {
  if (!Array.isArray(v)) return [];
  return v.map(String);
}
