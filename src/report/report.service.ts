import { Injectable } from '@nestjs/common';
import { StructuredLogger } from '../common/logger/logger.service.js';
import {
  AnalysisReport,
  AgentAnalysisResult,
  PreprocessorOutput,
  PreprocessingFinding,
  DomainFinding,
  VerdictedStaticFinding,
  VerdictedDomainFinding,
  DynamicVerdictedFinding,
  DomainNavigationLog,
  SandboxDomainObservation,
} from '../common/interfaces/analysis.interfaces.js';

const FILE_TYPE_LABEL: Record<string, string> = {
  content_script: 'content script',
  background: 'background',
  popup: 'popup',
  options_ui: 'página de opciones',
  devtools: 'devtools page',
  sandbox: 'sandbox page',
  override_page: 'override page',
  side_panel: 'side panel',
  library: 'librería',
  unknown: 'archivo',
  manifest: 'manifest',
};

const ROLE_CONTEXT: Record<string, string> = {
  content_script:
    'Un content script corre dentro de las páginas que visitas, por eso puede leer o modificar el DOM de esos sitios si tiene permisos de host.',
  background:
    'Un background/service worker corre de forma persistente o por eventos; suele coordinar permisos privilegiados, red y mensajería.',
  popup:
    'Un popup solo corre cuando abres la interfaz de la extensión; una lectura o evento aquí suele ser menos grave que el mismo patrón dentro de una página visitada.',
  options_ui:
    'La página de opciones normalmente maneja configuración; aun así, no debería exfiltrar datos sensibles ni ejecutar código dinámico.',
  manifest:
    'El manifest define capacidades y superficie de ataque, aunque por sí solo no prueba abuso.',
  unknown:
    'Este archivo no tiene un rol claro en el manifest; eso reduce la certeza y exige revisar si es alcanzable.',
};

/**
 * Confidence threshold above which a static finding is considered a confirmed
 * "positivo". Below this the finding is downgraded to "falso_positivo" — it
 * still ships in `estructura.resultado1` (so the frontend can inspect it) but
 * does not appear in the narrative arrays the user actually reads.
 */
const POSITIVE_CONFIDENCE_THRESHOLD = 0.7;

@Injectable()
export class ReportService {
  constructor(private readonly logger: StructuredLogger) {}

  /**
   * Builds the final report from:
   *  - the deterministic static-analysis output (resultado1, resultado2_*)
   *  - the agent results (Agent 1 = intent narrative, Agent 2 = dynamic verdict)
   *  - the raw Stagehand observations (for the per-domain timeline)
   *
   * Verdicts on static findings are derived from each finding's `confidence`
   * (above 0.7 → "positivo"). This replaces the LLM-per-finding loop that the
   * old Agent 2/Agent 3 used.
   */
  generateReport(
    jobId: string,
    extensionId: string,
    analysisDuration: number,
    metadata: {
      name?: string;
      version?: string;
      author?: string;
      crxHash: string;
    },
    preprocessed: PreprocessorOutput,
    agentAnalysis: AgentAnalysisResult,
    domainObservations: SandboxDomainObservation[] = [],
    riskScore?: AnalysisReport['puntuacion_riesgo'],
  ): AnalysisReport {
    const resultado1 = preprocessed.resultado1.map((f) =>
      this.verdictStatic(f),
    );
    const priority = preprocessed.resultado2_priority.map((f) =>
      this.verdictDomain(f),
    );
    const unknown = preprocessed.resultado2_unknown.map((f) =>
      this.verdictDomain(f),
    );
    const dinamico = agentAnalysis.agent2 ?? [];

    const navegacionDominios: DomainNavigationLog[] = domainObservations.map(
      (o) => ({
        domain: o.domain,
        url: o.url,
        navigatorUsed: o.navigatorUsed,
        honeypotSessionUsed: o.honeypotSessionUsed,
        agentSteps: o.agentSteps,
        actionsPerformed: o.actionsPerformed,
        error: o.error,
      }),
    );

    const dominios = this.uniqueDomainsFromPriority(priority);

    // Per-finding narratives are ALWAYS deterministic — they come from the
    // static-analysis rules + the report formatter, never from the LLM agent.
    // Agent 1 only contributes the holistic verdict + explanation (see
    // `agente1.explicacion`), shown separately in the drawer header. This keeps
    // the static analysis independent and reproducible.
    const hallazgosEstaticos = [
      ...resultado1
        .filter((f) => f.veredicto === 'positivo')
        .map((f) => this.formatStatic(f)),
      ...[...priority, ...unknown]
        .filter((f) => f.veredicto === 'positivo')
        .map((f) => this.formatStaticDomain(f)),
    ];
    const hallazgosDinamicos = dinamico
      .filter(
        (f) => f.veredicto === 'maliciosa' || f.veredicto === 'sospechosa',
      )
      .map((f) => this.formatDynamic(f));

    this.logger.logWithJob(
      jobId,
      'info',
      `Report generated: ${hallazgosEstaticos.length} static (incl. domain references), ${hallazgosDinamicos.length} dynamic findings`,
      'ReportService',
    );

    return {
      jobId,
      extensionId,
      extensionName: metadata.name,
      extensionVersion: metadata.version,
      extensionAuthor: metadata.author,
      crxHash: metadata.crxHash,
      analysisTimestamp: new Date(),
      analysisDuration,
      agente1: agentAnalysis.agent1,
      dominios_contactados_prioritarios: dominios,
      hallazgos_estaticos_positivos: hallazgosEstaticos,
      hallazgos_dinamicos_positivos: hallazgosDinamicos,
      estructura: {
        resultado1,
        resultado2_priority: priority,
        resultado2_unknown: unknown,
        resultado_dinamico: dinamico,
      },
      navegacionDominios,
      puntuacion_riesgo: riskScore,
    };
  }

  // ─── Verdict derivation (rule-based, no LLM) ──────────────────────────────

  private verdictStatic(finding: PreprocessingFinding): VerdictedStaticFinding {
    const confidence = finding.confidence ?? 0;
    const isPositive = confidence >= POSITIVE_CONFIDENCE_THRESHOLD;
    return {
      ...finding,
      veredicto: isPositive ? 'positivo' : 'falso_positivo',
      razon:
        finding.why ??
        (isPositive
          ? `Hallazgo confirmado por análisis estático (confianza ${Math.round(confidence * 100)}%)`
          : `Señal débil (confianza ${Math.round(confidence * 100)}%); preservado en estructura para inspección`),
    };
  }

  private verdictDomain(finding: DomainFinding): VerdictedDomainFinding {
    // Priority categories are always considered "positivo" — they were chosen
    // precisely because they represent sensitive contact surfaces (financial,
    // identity, LLM, etc.). The "razon" describes the category match.
    return {
      ...finding,
      veredicto: 'positivo',
      razon:
        finding.category === 'desconocido'
          ? `Dominio desconocido referenciado por la extensión (${finding.discoveryType === 'host_permission_manifest' ? 'declarado en host_permissions' : 'aparece en código'})`
          : `Categoría ${finding.category} — dominio sensible relevante para el reporte`,
    };
  }

  // ─── Formatters ───────────────────────────────────────────────────────────

  private formatStatic(f: VerdictedStaticFinding): string {
    const fileType = FILE_TYPE_LABEL[f.fileType] ?? f.fileType;
    const roleContext = ROLE_CONTEXT[f.fileType] ?? '';
    const snippet = f.codeSnippet ? ` Fragmento: ${f.codeSnippet}` : '';
    const confidence =
      typeof f.confidence === 'number'
        ? ` Confianza: ${Math.round(f.confidence * 100)}%.`
        : '';
    const explanation = f.why || f.razon;
    return (
      `En el ${fileType} de la extensión (${f.filePath}, línea ${f.line}) encontramos ${this.describeStaticFinding(f)} ` +
      `${explanation} ${roleContext} ${f.razon}${snippet}${confidence}`
    );
  }

  private formatStaticDomain(f: VerdictedDomainFinding): string {
    const fileType = FILE_TYPE_LABEL[f.fileType] ?? f.fileType;
    return (
      `En el ${fileType} de la extensión (${f.filePath}, línea ${f.line}) encontramos referencia al dominio ${f.domain}, ` +
      `clasificado como ${f.category}. ${f.razon}`
    );
  }

  private formatDynamic(f: DynamicVerdictedFinding): string {
    const fileType = FILE_TYPE_LABEL[f.fileType] ?? f.fileType;
    const detail = `${f.domain} clasificado como ${f.category}`;
    return (
      `En el ${fileType} de la extensión, en la ruta ${f.filePath}, línea ${f.line}, ` +
      `descubrimos que ${f.discoveryType} (${detail}), porque ${f.accion_hecha}, por tanto ${f.razon}`
    );
  }

  private uniqueDomainsFromPriority(
    priority: VerdictedDomainFinding[],
  ): string[] {
    const set = new Set<string>();
    for (const f of priority) {
      set.add(`https://${f.domain}`);
    }
    return [...set];
  }

  private describeStaticFinding(f: VerdictedStaticFinding): string {
    if (f.discoveryType === 'flujo_datos_a_red') {
      return `un flujo de datos sensible hacia una salida de red: ${f.detail}.`;
    }
    if (f.discoveryType === 'lectura_cookies') {
      return `acceso a cookies mediante ${f.detail}; esto puede exponer identificadores de sesión.`;
    }
    if (f.discoveryType === 'lectura_storage_navegador') {
      return `lectura de almacenamiento del navegador mediante ${f.detail}; ahí pueden existir tokens o estado de sesión.`;
    }
    if (f.discoveryType === 'listener_teclado') {
      return `un listener de entrada/teclado (${f.detail}); en páginas visitadas puede capturar credenciales o formularios.`;
    }
    if (f.discoveryType === 'inyeccion_dom') {
      return `inyección o modificación de DOM/script (${f.detail}); esto puede alterar páginas o ejecutar código adicional.`;
    }
    if (f.discoveryType === 'funcion_javascript_riesgosa') {
      return `uso de una función sensible (${f.detail}); el riesgo depende de los datos que procesa y del destino.`;
    }
    if (f.discoveryType === 'permiso_chrome_manifest_riesgoso') {
      return `un permiso con alto impacto potencial (${f.detail}).`;
    }
    if (f.discoveryType === 'correlacion_riesgo') {
      return `una combinación de señales que aumenta el riesgo: ${f.detail}.`;
    }
    return `${f.discoveryType} (${f.detail}).`;
  }
}
