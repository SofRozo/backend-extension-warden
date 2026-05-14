import { Injectable } from '@nestjs/common';
import { LlmClientService } from '../llm/llm-client.service.js';
import { StructuredLogger } from '../../common/logger/logger.service.js';
import type {
  PreprocessorOutput,
  PreprocessingFinding,
  DomainFinding,
  DynamicVerdictedFinding,
  SandboxDomainObservation,
  ProcessedFile,
  FileRole,
} from '../../common/interfaces/analysis.interfaces.js';
import type {
  Agent1Output,
  AgentFinding,
} from '../interfaces/agents.interfaces.js';

const PROMPT = `Eres un auditor de seguridad de extensiones de navegador. Recibes TODA la
evidencia recolectada (manifest, código fuente de los scripts, hallazgos
estáticos deterministas, dominios contactados, observaciones del análisis
dinámico). Tu trabajo es doble:

A) Producir un VEREDICTO HOLÍSTICO de la extensión (propósito real, veredicto,
   nivel de riesgo, explicación ejecutiva).

B) Revisar el CÓDIGO FUENTE entregado y reportar hallazgos adicionales en el
   campo "hallazgos_propios". Estos son items que tú detectaste leyendo el
   código directamente, COMPLEMENTANDO al análisis estático determinista que
   ya corrió por reglas. Útil para:
   - Strings codificadas/ofuscadas que decodifican a URLs o comandos.
   - Lógica condicional sospechosa (chequeos de hora, fecha, idioma, geo,
     anti-debugging, anti-emulación).
   - Cadenas con apariencia de C2 (endpoints inusuales, IPs hardcoded,
     subdominios DGA, paths con parámetros raros).
   - Uso peculiar de APIs (chrome.storage como buffer de exfiltración,
     chrome.scripting con argumentos dinámicos, mensajería peer-to-peer
     no documentada).
   - Comportamientos polimórficos, modos de "fail-quiet", traps en
     desarrolladores.
   - Patrones que las reglas estáticas no detectan por ser muy específicos
     a este código.

NO duplices hallazgos que YA aparecen en la lista determinista — la idea es
que tu trabajo es complementario, no redundante. Si solo confirmas lo
determinista, devuelve hallazgos_propios = [].

REGLAS DE INTERPRETACIÓN:
- Los hallazgos estáticos vienen con un campo "confianza" (0-1). Hallazgos
  con confianza >= 0.7 son CONFIRMADOS; los demás son señales débiles.
- NO marques "critico" solo por permisos amplios, archivos no resueltos,
  minificación, lecturas aisladas de cookies, o muchas ocurrencias repetidas.
  "critico" exige evidencia clara: keylogger, robo de cookies de sesión,
  lectura de contraseñas/frases semilla con envío a red, script remoto MV3,
  exfiltración confirmada por flujo de datos, o comportamiento dinámico
  malicioso.
- Un hallazgo en popup/interfaz de extensión es menos grave que el mismo patrón
  dentro de un content script. Un valor llamado "seed" en juegos/mascotas puede
  ser una semilla aleatoria de gameplay, no una frase semilla de wallet.
- En extensiones de seguridad/adblockers, reglas o scriptlets que leen/escriben
  cookies pueden ser parte esperada del bloqueo de banners o filtros. Solo
  trátalo como robo si hay envío a red, almacenamiento abusivo o contradicción
  clara con el propósito.
- Un dominio en categoría "sensible_financiero|identidad|llm|correo|redes|
  gob|data_broker" contactado por una extensión que no declara esa función
  es una señal fuerte.
- Si un patrón de exfiltración estático coincide con un comportamiento
  dinámico (ej. fetch a dominio sensible + Agent 2 emite "maliciosa"),
  refleja ese refuerzo en "explicacion".

EVIDENCIA:
{evidencia}

CÓDIGO FUENTE:
{codigo}

Responde EXACTAMENTE con un JSON con esta forma (sin texto adicional):
{
  "proposito": "descripción del propósito real de la extensión",
  "categoria": "productividad|entretenimiento|seguridad|utilidad|red_social|compras|otro",
  "acciones_esperadas": ["...", "..."],
  "acciones_NO_esperadas": ["...", "..."],
  "senales_alarma_manifest": ["...", "..."],
  "nivel_riesgo_inicial": "bajo|medio|alto|critico",
  "razon_nivel_riesgo": "explicación breve del nivel de riesgo",
  "veredicto_global": "maliciosa|sospechosa|benigna",
  "explicacion": "2-4 oraciones que el usuario lee como resumen ejecutivo",
  "hallazgos_propios": [
    {
      "archivo": "ruta/al/archivo.js",
      "linea": 42,
      "tipo": "exfiltración|obfuscación|anti-análisis|C2|abuso_api|...",
      "descripcion": "qué viste y por qué importa, en una oración",
      "severidad": "bajo|medio|alto|critico",
      "snippet": "fragmento corto del código (opcional)"
    }
  ]
}`;

const VALID_RISK_LEVELS = new Set(['bajo', 'medio', 'alto', 'critico']);
const VALID_VERDICTS = new Set(['maliciosa', 'sospechosa', 'benigna']);
const VALID_SEVERIDADES = new Set(['bajo', 'medio', 'alto', 'critico']);

/** Per-file truncation when including source in the prompt. Most extension
 *  scripts are short; very large files get truncated with a marker so the LLM
 *  knows there is more code. */
const MAX_LINES_PER_FILE = 600;

/** Total character budget for the source-code block. 120 KB ≈ ~30K tokens —
 *  fits comfortably in qwen3.5:9b's 32K context window and is a fraction of
 *  Gemini Flash's 1M context. */
const MAX_TOTAL_SOURCE_CHARS = 120_000;

/** Per-finding snippet cap in the deterministic-findings summary, just to
 *  prevent runaway lines. */
const MAX_DET_FINDING_SNIPPET = 240;
const MAX_AGENT_STATIC_FINDINGS = 120;

@Injectable()
export class Agent1IntentionService {
  constructor(
    private readonly llm: LlmClientService,
    private readonly logger: StructuredLogger,
  ) {}

  /**
   * Holistic analysis. Receives the full evidence bundle PLUS the actual
   * source code of every non-library, non-obfuscated script, and returns:
   *   1. The high-level verdict and explanation.
   *   2. An OPTIONAL list of findings the agent discovered by reading the
   *      code (`hallazgos_propios`). These are independent of the
   *      deterministic findings and complement them.
   *
   * The caller (orchestrator/processor) is responsible for collecting the
   * evidence in the right order; this service does NOT trigger other agents.
   */
  async analyze(
    preprocessed: PreprocessorOutput,
    jobId: string,
    extras: {
      dynamicObservations?: SandboxDomainObservation[];
      dynamicVerdicts?: DynamicVerdictedFinding[];
    } = {},
  ): Promise<Agent1Output> {
    const { manifest, files } = preprocessed;

    const fileList = files
      .filter((f) => f.role !== 'library')
      .map(
        (f) =>
          `  - ${f.path} [${f.role}${f.isObfuscated ? ', OFUSCADO' : ''}${f.isMinified ? ', MINIFICADO' : ''}]`,
      )
      .join('\n');

    const evidencia = JSON.stringify(
      {
        nombre: manifest.name,
        descripcion: manifest.description ?? '(sin descripción)',
        manifest_version: manifest.manifestVersion,
        permisos_api: manifest.apiPermissions,
        host_permissions: manifest.hostPermissions,
        optional_permissions: manifest.optionalPermissions,
        content_scripts_activos_en: manifest.contentScripts.flatMap(
          (cs) => cs.matches,
        ),
        background:
          manifest.serviceWorker ?? manifest.backgroundScripts ?? null,
        popup: manifest.popupUrl ?? null,
        archivos_clasificados: `\n${fileList}`,
        hallazgos_estaticos_deterministas: this.summariseStatic(
          preprocessed.resultado1,
        ),
        dominios_prioritarios: this.summariseDomains(
          preprocessed.resultado2_priority,
        ),
        dominios_desconocidos: this.summariseDomains(
          preprocessed.resultado2_unknown,
        ),
        veredictos_dinamicos: this.summariseDynamicVerdicts(
          extras.dynamicVerdicts ?? [],
        ),
        observaciones_dinamicas: this.summariseDynamicObservations(
          extras.dynamicObservations ?? [],
        ),
        puntuacion_riesgo: preprocessed.riskScore ?? null,
      },
      null,
      2,
    );

    const codigo = this.buildSourceCodeBlock(files, preprocessed.resultado1);

    const prompt = PROMPT.replace('{evidencia}', evidencia).replace(
      '{codigo}',
      codigo.text,
    );

    this.logger.logWithJob(
      jobId,
      'info',
      `Agent 1 holistic — manifest + ${preprocessed.resultado1.length} static findings + ` +
        `${preprocessed.resultado2_priority.length} priority + ${preprocessed.resultado2_unknown.length} unknown domains + ` +
        `${extras.dynamicVerdicts?.length ?? 0} dynamic verdicts + ` +
        `${codigo.filesIncluded}/${codigo.filesTotal} source files (${codigo.chars} chars)`,
      'Agent1IntentionService',
    );

    const raw = await this.llm.callLLM(prompt, jobId);
    return this.validate(raw, jobId);
  }

  // ─── Evidence summarisers (no caps — let the agent see everything) ──────

  private summariseStatic(
    findings: PreprocessingFinding[],
  ): Array<Record<string, unknown>> {
    // The full list is preserved in `report.estructura.resultado1`, but the
    // holistic agent gets a compact, signal-first view. Thousands of repeated
    // ruleset/scriptlet findings otherwise cause the model to overreact.
    const grouped = new Map<string, PreprocessingFinding & { count?: number }>();
    for (const f of findings) {
      if ((f.confidence ?? 0) < 0.5) continue;
      const key =
        f.discoveryType === 'lectura_cookies'
          ? `${f.discoveryType}:${f.fileType}:document.cookie`
          : `${f.discoveryType}:${f.fileType}:${f.detail}`;
      const current = grouped.get(key);
      if (!current) {
        grouped.set(key, { ...f, count: 1 });
        continue;
      }
      current.count = (current.count ?? 1) + 1;
      if ((f.confidence ?? 0) > (current.confidence ?? 0)) {
        grouped.set(key, { ...f, count: current.count });
      }
    }

    const ordered: Array<Record<string, unknown>> = [...grouped.values()]
      .slice()
      .sort((a, b) => (b.confidence ?? 0) - (a.confidence ?? 0))
      .slice(0, MAX_AGENT_STATIC_FINDINGS)
      .map((f) => ({
        archivo: f.filePath,
        rol: f.fileType,
        linea: f.line,
        tipo: f.discoveryType,
        detalle: f.detail,
        ocurrencias_similares: f.count ?? 1,
        severidad: f.severity,
        confianza: f.confidence,
        por_que: f.why,
        snippet: f.codeSnippet?.slice(0, MAX_DET_FINDING_SNIPPET),
      }));

    const omitted = grouped.size - ordered.length;
    if (omitted > 0) {
      ordered.push({
        tipo: 'resumen_omitidos',
        detalle: `${omitted} grupo(s) de hallazgos estáticos de menor prioridad fueron omitidos del prompt del agente; siguen en la estructura técnica.`,
      });
    }
    return ordered;
  }

  private summariseDomains(
    findings: DomainFinding[],
  ): Array<Record<string, unknown>> {
    return findings.map((f) => ({
      archivo: f.filePath,
      rol: f.fileType,
      linea: f.line,
      dominio: f.domain,
      categoria: f.category,
      origen:
        f.discoveryType === 'host_permission_manifest'
          ? 'manifest.host_permissions'
          : 'en código',
    }));
  }

  private summariseDynamicVerdicts(
    verdicts: DynamicVerdictedFinding[],
  ): Array<Record<string, unknown>> {
    return verdicts.map((v) => ({
      dominio: v.domain,
      categoria: v.category,
      veredicto: v.veredicto,
      accion_hecha: v.accion_hecha,
      razon: v.razon,
    }));
  }

  private summariseDynamicObservations(
    observations: SandboxDomainObservation[],
  ): Array<Record<string, unknown>> {
    return observations.map((o) => ({
      dominio: o.domain,
      url: o.url,
      navegador: o.navigatorUsed,
      requests: o.requestsToThisDomain,
      dom_modificado: o.domModificationsDetected,
      credenciales_enviadas: o.credentialsSubmitted,
      observaciones: o.observations,
      acciones: o.actionsPerformed,
      error: o.error,
    }));
  }

  // ─── Source-code block construction ──────────────────────────────────────

  /**
   * Assembles the source-code block. Files are ordered by relevance:
   *   1. Files referenced by the deterministic findings (highest signal).
   *   2. Files with sensitive roles (content_script, background, service worker).
   *   3. Everything else.
   * Libraries and obfuscated bundles are skipped (libraries are noise; the
   * deobfuscated code is what gets included if available — see ProcessedFile.cleanCode).
   */
  private buildSourceCodeBlock(
    files: ProcessedFile[],
    deterministicFindings: PreprocessingFinding[],
  ): {
    text: string;
    chars: number;
    filesIncluded: number;
    filesTotal: number;
  } {
    const findingFileSet = new Set(
      deterministicFindings.map((f) => f.filePath),
    );
    const SENSITIVE_ROLES: FileRole[] = [
      'content_script',
      'background',
      'options_ui',
      'devtools',
      'override_page',
      'sandbox',
      'side_panel',
      'popup',
    ];

    const candidates = files
      .filter((f) => f.role !== 'library' && (f.cleanCode || !f.isObfuscated))
      .map((f) => {
        let score = 0;
        if (findingFileSet.has(f.path)) score += 10;
        if (SENSITIVE_ROLES.includes(f.role)) score += 5;
        if (f.isObfuscated) score += 8; // worth a manual look even if just header
        if (f.role === 'unknown') score += 1;
        return { file: f, score };
      })
      .sort((a, b) => b.score - a.score);

    const parts: string[] = [];
    let totalChars = 0;
    let included = 0;
    let truncatedFiles = 0;

    for (const { file } of candidates) {
      if (totalChars >= MAX_TOTAL_SOURCE_CHARS) {
        truncatedFiles++;
        continue;
      }
      const code = (file.cleanCode ?? '').trim();
      if (!code) continue;

      const lines = code.split('\n');
      const linesShown = lines.slice(0, MAX_LINES_PER_FILE).join('\n');
      const truncatedNotice =
        lines.length > MAX_LINES_PER_FILE
          ? `\n// … (${lines.length - MAX_LINES_PER_FILE} líneas más omitidas)`
          : '';
      const header = `\n// ─── ${file.path} [${file.role}${file.isObfuscated ? ', OFUSCADO' : ''}] ─────────────────────────`;
      const block = `${header}\n${linesShown}${truncatedNotice}`;

      if (totalChars + block.length > MAX_TOTAL_SOURCE_CHARS) {
        // Truncate the last block to fit the remaining budget so the LLM at
        // least sees the header + the first lines.
        const remaining = MAX_TOTAL_SOURCE_CHARS - totalChars;
        if (remaining > header.length + 200) {
          const fitted =
            block.slice(0, remaining - 50) + '\n// … (cortado por presupuesto)';
          parts.push(fitted);
          totalChars += fitted.length;
          included++;
        } else {
          truncatedFiles++;
        }
        break;
      }
      parts.push(block);
      totalChars += block.length;
      included++;
    }

    if (truncatedFiles > 0) {
      parts.push(
        `\n// (${truncatedFiles} archivo(s) adicionales no incluido(s) por presupuesto de contexto.)`,
      );
    }

    return {
      text: parts.join('\n') || '// (sin código fuente disponible)',
      chars: totalChars,
      filesIncluded: included,
      filesTotal: candidates.length,
    };
  }

  // ─── Validation ──────────────────────────────────────────────────────────

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

    const veredictoRaw = r.veredicto_global ?? 'sospechosa';
    const veredicto = VALID_VERDICTS.has(veredictoRaw)
      ? veredictoRaw
      : 'sospechosa';
    if (!VALID_VERDICTS.has(veredictoRaw)) {
      this.logger.logWithJob(
        jobId,
        'warn',
        `Agent 1 returned unexpected veredicto_global="${veredictoRaw}", defaulting to "sospechosa"`,
        'Agent1IntentionService',
      );
    }

    return {
      proposito: String(r.proposito),
      categoria: String(r.categoria ?? 'otro'),
      acciones_esperadas: toStringArray(r.acciones_esperadas),
      acciones_NO_esperadas: toStringArray(r.acciones_NO_esperadas),
      senales_alarma_manifest: toStringArray(r.senales_alarma_manifest),
      nivel_riesgo_inicial: VALID_RISK_LEVELS.has(nivel) ? nivel : 'medio',
      razon_nivel_riesgo: String(r.razon_nivel_riesgo ?? ''),
      veredicto_global: veredicto,
      explicacion: String(r.explicacion ?? ''),
      hallazgos_propios: this.sanitiseFindings(r.hallazgos_propios),
    };
  }

  private sanitiseFindings(raw: unknown): AgentFinding[] | undefined {
    if (!Array.isArray(raw)) return undefined;
    const cleaned: AgentFinding[] = [];
    for (const item of raw) {
      if (!item || typeof item !== 'object') continue;
      const it = item as Record<string, unknown>;
      const archivo = typeof it.archivo === 'string' ? it.archivo : '';
      const descripcion =
        typeof it.descripcion === 'string' ? it.descripcion : '';
      const tipo = typeof it.tipo === 'string' ? it.tipo : 'otro';
      if (!archivo || !descripcion) continue;
      const severidadRaw =
        typeof it.severidad === 'string' ? it.severidad.toLowerCase() : 'medio';
      const severidad = VALID_SEVERIDADES.has(severidadRaw)
        ? (severidadRaw as AgentFinding['severidad'])
        : 'medio';
      const linea =
        typeof it.linea === 'number' && Number.isFinite(it.linea)
          ? it.linea
          : undefined;
      const snippet =
        typeof it.snippet === 'string' ? it.snippet.slice(0, 300) : undefined;
      cleaned.push({ archivo, linea, tipo, descripcion, severidad, snippet });
    }
    return cleaned.length > 0 ? cleaned : undefined;
  }
}

function toStringArray(v: unknown): string[] {
  if (!Array.isArray(v)) return [];
  return v.map(String);
}
