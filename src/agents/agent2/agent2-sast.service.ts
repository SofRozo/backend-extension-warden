import { Injectable } from '@nestjs/common';
import { LlmClientService } from '../llm/llm-client.service.js';
import { StructuredLogger } from '../../common/logger/logger.service.js';
import type {
  PreprocessorOutput,
  PreprocessingFinding,
  VerdictedStaticFinding,
  VerdictPositive,
} from '../../common/interfaces/analysis.interfaces.js';
import type { Agent1Output } from '../interfaces/agents.interfaces.js';

const PROMPT = `Eres un experto en seguridad de extensiones de navegador.

Recibes la lista COMPLETA de hallazgos estáticos detectados por el preprocesamiento.
Tu tarea es decidir, para CADA UNO, si es un hallazgo real ("positivo") o un falso positivo ("falso_positivo")
y justificar tu decisión en 1-2 oraciones, considerando el rol del archivo y el propósito declarado.

REGLAS CONTEXTUALES:
- Un listener keydown/input en POPUP es UX normal del popup → falso_positivo.
  En content_script o background sin razón clara → positivo (potencial keylogger).
- innerHTML asignado en POPUP mostrando datos al usuario → falso_positivo.
  innerHTML leído del DOM en content_script y enviado a red → positivo.
- chrome.storage.local en una extensión que declara persistencia → falso_positivo.
  chrome.cookies.getAll en una extensión de mascota virtual → positivo (no hay justificación).
- fetch en background puede ser legítimo si el propósito declarado lo amerita.
- Código ofuscado SIEMPRE es positivo independiente del contexto.
- script_remoto_mv3 es SIEMPRE positivo (violación de política MV3).

PROPÓSITO DECLARADO (Agente 1):
{contexto_agente1}

LISTA DE HALLAZGOS A EVALUAR (debes devolver TODOS, en el mismo orden):
{hallazgos}

Responde EXACTAMENTE con un JSON con esta forma (sin texto adicional):
{
  "evaluaciones": [
    {
      "indice": 0,
      "veredicto": "positivo" | "falso_positivo",
      "razon": "explicación breve"
    },
    ...
  ]
}

DEBES devolver una entrada por cada hallazgo numerado en la lista, en el mismo orden.`;

const VALID_VERDICTS: VerdictPositive[] = ['positivo', 'falso_positivo'];

@Injectable()
export class Agent2SastService {
  constructor(
    private readonly llm: LlmClientService,
    private readonly logger: StructuredLogger,
  ) {}

  /**
   * Iterates 1:1 over preprocessed.resultado1 and returns a verdicted copy.
   * Falls back to "positivo" with a generic reason when the LLM omits a
   * particular finding so the output array is always the same length as input.
   */
  async analyze(
    preprocessed: PreprocessorOutput,
    agent1: Agent1Output,
    jobId: string,
  ): Promise<VerdictedStaticFinding[]> {
    const resultado1 = preprocessed.resultado1;

    if (resultado1.length === 0) {
      this.logger.logWithJob(
        jobId,
        'info',
        'Agent 2 — resultado1 vacío, no hay nada que evaluar',
        'Agent2SastService',
      );
      return [];
    }

    const contextoAgente1 = JSON.stringify(
      {
        proposito: agent1.proposito,
        categoria: agent1.categoria,
        acciones_esperadas: agent1.acciones_esperadas,
        acciones_NO_esperadas: agent1.acciones_NO_esperadas,
        nivel_riesgo_inicial: agent1.nivel_riesgo_inicial,
      },
      null,
      2,
    );

    const hallazgosTexto = resultado1
      .map(
        (f, i) =>
          `[${i}] fileType=${f.fileType} | filePath=${f.filePath} | line=${f.line} | ` +
          `discoveryType=${f.discoveryType} | detail=${f.detail}` +
          (f.codeSnippet ? `\n    código: ${f.codeSnippet.slice(0, 200)}` : ''),
      )
      .join('\n');

    const prompt = PROMPT.replace('{contexto_agente1}', contextoAgente1).replace(
      '{hallazgos}',
      hallazgosTexto,
    );

    this.logger.logWithJob(
      jobId,
      'info',
      `Agent 2 — evaluating ${resultado1.length} resultado1 findings`,
      'Agent2SastService',
    );

    let raw: unknown;
    try {
      raw = await this.llm.callLLM(prompt, jobId);
    } catch (err) {
      this.logger.logWithJob(
        jobId,
        'warn',
        `Agent 2 LLM call failed: ${err instanceof Error ? err.message : String(err)}`,
        'Agent2SastService',
      );
      return resultado1.map((f) => this.fallback(f, 'LLM no disponible'));
    }

    return this.mergeVerdicts(resultado1, raw, jobId);
  }

  // ─── Helpers ───────────────────────────────────────────────────────────────

  private mergeVerdicts(
    findings: PreprocessingFinding[],
    raw: unknown,
    jobId: string,
  ): VerdictedStaticFinding[] {
    const r = raw as { evaluaciones?: Array<Record<string, unknown>> };
    const byIndex = new Map<number, { veredicto: VerdictPositive; razon: string }>();

    if (Array.isArray(r?.evaluaciones)) {
      for (const e of r.evaluaciones) {
        const idx =
          typeof e.indice === 'number'
            ? e.indice
            : Number.parseInt(String(e.indice ?? ''), 10);
        if (!Number.isInteger(idx) || idx < 0 || idx >= findings.length) continue;
        const veredicto = String(e.veredicto ?? 'positivo') as VerdictPositive;
        byIndex.set(idx, {
          veredicto: VALID_VERDICTS.includes(veredicto) ? veredicto : 'positivo',
          razon: String(e.razon ?? ''),
        });
      }
    }

    if (byIndex.size !== findings.length) {
      this.logger.logWithJob(
        jobId,
        'warn',
        `Agent 2 returned ${byIndex.size}/${findings.length} verdicts; missing entries default to "positivo"`,
        'Agent2SastService',
      );
    }

    return findings.map((f, i) => {
      const v = byIndex.get(i);
      if (!v) return this.fallback(f, 'Agente 2 no emitió veredicto explícito');
      return { ...f, veredicto: v.veredicto, razon: v.razon };
    });
  }

  private fallback(
    f: PreprocessingFinding,
    razon: string,
  ): VerdictedStaticFinding {
    return { ...f, veredicto: 'positivo', razon };
  }
}
