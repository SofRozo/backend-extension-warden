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
import { UserRiskSummaryService } from './user-risk/user-risk-summary.service.js';

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
    'Esto significa que este archivo se inyecta y vive directamente adentro de las páginas web que visitas (como tu correo o tus redes sociales), por lo que puede leer o modificar todo lo que ves y escribes en la pantalla.',
  background:
    'Este es el "cerebro invisible" de la extensión. Corre en segundo plano todo el tiempo en tu navegador sin que te des cuenta, comunicándose con servidores en Internet y procesando datos.',
  popup:
    'Este archivo pertenece a la ventanita visual que se abre únicamente cuando haces clic en el ícono de la extensión en la barra de Chrome.',
  options_ui:
    'Este archivo corresponde a la página de configuración de la extensión.',
  manifest:
    'Este es el archivo de configuración donde la extensión le pide los permisos iniciales a Chrome.',
  unknown:
    'Este archivo está suelto dentro de la extensión y no sabemos en qué momento exacto se ejecuta.',
};

/**
 * Confidence threshold above which a static finding is considered a confirmed
 * "positivo". Below this the finding is downgraded to "falso_positivo" — it
 * still ships in `estructura.resultado1` (so the frontend can inspect it) but
 * does not appear in the narrative arrays the user actually reads.
 */
const POSITIVE_CONFIDENCE_THRESHOLD = 0.7;
const STATIC_NARRATIVE_LIMIT = 12;
const DOMAIN_NARRATIVE_LIMIT = 5;

@Injectable()
export class ReportService {
  constructor(
    private readonly logger: StructuredLogger,
    private readonly userRiskSummary: UserRiskSummaryService,
  ) {}

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
    const resumenUsuario = this.userRiskSummary.buildSummary(
      preprocessed,
      resultado1,
      [...priority, ...unknown],
      dinamico,
    );
    const veredictoUsuario = this.userRiskSummary.buildVerdict(resumenUsuario);

    // Per-finding narratives are ALWAYS deterministic — they come from the
    // static-analysis rules + the report formatter, never from the LLM agent.
    // Agent 1 only contributes the holistic verdict + explanation (see
    // `agente1.explicacion`), shown separately in the drawer header. This keeps
    // the static analysis independent and reproducible.
    const hallazgosEstaticos = [
      ...this.buildStaticNarratives(
        resultado1.filter((f) => f.veredicto === 'positivo'),
      ),
      ...this.buildDomainNarratives(
        [...priority, ...unknown].filter((f) => f.veredicto === 'positivo'),
      ),
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
      resumen_usuario: resumenUsuario,
      veredicto_usuario: veredictoUsuario,
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
    const confidence =
      typeof f.confidence === 'number'
        ? ` Confianza: ${Math.round(f.confidence * 100)}%.`
        : '';
    const explanation = this.humanizeReason(f.why || f.razon);
    return (
      `En el ${fileType} (${f.filePath}, línea ${f.line}) detectamos ${this.describeStaticFinding(f)} ` +
      `Motivo: ${explanation}${roleContext ? ` Contexto: ${roleContext}` : ''}${confidence}`
    );
  }

  private formatStaticDomain(f: VerdictedDomainFinding): string {
    const fileType = FILE_TYPE_LABEL[f.fileType] ?? f.fileType;
    const origin =
      f.discoveryType === 'host_permission_manifest'
        ? 'declarado como permiso de host'
        : 'contactado por el código';
    return (
      `En el ${fileType} (${f.filePath}, línea ${f.line}) encontramos el dominio ${f.domain}, ${origin}, ` +
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

  private buildStaticNarratives(findings: VerdictedStaticFinding[]): string[] {
    const groups = new Map<
      string,
      { first: VerdictedStaticFinding; count: number; priority: number }
    >();

    for (const finding of findings) {
      const key = this.staticNarrativeGroupKey(finding);
      const priority = this.staticNarrativePriority(finding);
      const current = groups.get(key);
      if (!current) {
        groups.set(key, { first: finding, count: 1, priority });
        continue;
      }
      current.count += 1;
      if (priority > current.priority) {
        current.first = finding;
        current.priority = priority;
      }
    }

    const ordered = [...groups.values()].sort(
      (a, b) => b.priority - a.priority,
    );
    const selected = ordered.slice(0, STATIC_NARRATIVE_LIMIT);
    const omitted = ordered
      .slice(STATIC_NARRATIVE_LIMIT)
      .reduce((sum, group) => sum + group.count, 0);

    const narratives = selected.map((group) => {
      const extra =
        group.count > 1
          ? ` Encontramos ${group.count - 1} ocurrencia(s) similar(es), agrupadas para que el reporte sea legible.`
          : '';
      return `${this.formatStatic(group.first)}${extra}`;
    });

    if (omitted > 0) {
      narratives.push(
        `Además, se omitieron ${omitted} hallazgo(s) repetitivos o de menor prioridad en esta vista. Siguen disponibles en la estructura técnica del reporte.`,
      );
    }

    return narratives;
  }

  private buildDomainNarratives(findings: VerdictedDomainFinding[]): string[] {
    const ordered = [...findings].sort(
      (a, b) => (b.priority ?? 0) - (a.priority ?? 0),
    );
    const selected = ordered.slice(0, DOMAIN_NARRATIVE_LIMIT);
    const omitted = ordered.length - selected.length;
    const narratives = selected.map((f) => this.formatStaticDomain(f));
    if (omitted > 0) {
      narratives.push(
        `Además, se omitieron ${omitted} dominio(s) repetidos o de menor prioridad en esta vista.`,
      );
    }
    return narratives;
  }

  private staticNarrativeGroupKey(f: VerdictedStaticFinding): string {
    if (f.discoveryType === 'lectura_cookies') {
      return `${f.discoveryType}:${f.fileType}:document.cookie`;
    }
    if (f.discoveryType === 'lectura_storage_navegador') {
      return `${f.discoveryType}:${f.fileType}`;
    }
    if (
      f.discoveryType === 'dependencia_no_resuelta' ||
      f.discoveryType === 'archivo_huerfano' ||
      f.discoveryType === 'archivo_minificado'
    ) {
      return `${f.discoveryType}:${f.detail}`;
    }
    if (f.discoveryType === 'funcion_javascript_riesgosa') {
      return `${f.discoveryType}:${f.detail.split(':')[0]}`;
    }
    return `${f.discoveryType}:${f.filePath}:${f.detail}`;
  }

  private staticNarrativePriority(f: VerdictedStaticFinding): number {
    const typePriority: Partial<Record<string, number>> = {
      flujo_datos_a_red: 100,
      correlacion_riesgo: 95,
      script_remoto_mv3: 90,
      listener_teclado: 85,
      lectura_cookies: 80,
      lectura_storage_navegador: 75,
      inyeccion_dom: 70,
      codigo_ofuscado: 60,
      funcion_javascript_riesgosa: 50,
      permiso_chrome_manifest_riesgoso: 30,
      dependencia_no_resuelta: 10,
      archivo_huerfano: 8,
      archivo_minificado: 6,
    };
    const severityBoost =
      f.severity === 'critical'
        ? 8
        : f.severity === 'high'
          ? 5
          : f.severity === 'medium'
            ? 2
            : 0;
    return (
      (typePriority[f.discoveryType] ?? 20) +
      severityBoost +
      Math.round((f.confidence ?? 0) * 10)
    );
  }

  private uniqueDomainsFromPriority(
    priority: VerdictedDomainFinding[],
  ): string[] {
    const set = new Set<string>();
    for (const f of priority) {
      if (f.discoveryType !== 'url_en_codigo') continue;
      set.add(`https://${f.domain}`);
    }
    return [...set];
  }

  private describeStaticFinding(f: VerdictedStaticFinding): string {
    if (f.discoveryType === 'flujo_datos_a_red') {
      if (f.detail.includes('memoria oculta') || f.detail.includes('extension message')) {
        return `que la extensión está extrayendo tu información personal de esta página y pasándola a su código invisible en segundo plano (${f.detail}).`;
      }
      return `que la extensión está enviando tu información directamente a servidores en Internet (${f.detail}).`;
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
      if (
        f.detail.includes('sendMessage') ||
        f.detail.includes('postMessage')
      ) {
        return `uso de mensajería (${f.detail}); puede mover datos desde una página hacia un contexto con más permisos.`;
      }
      return `uso de una función sensible (${f.detail}); el riesgo depende de los datos que procesa y del destino.`;
    }
    if (f.discoveryType === 'permiso_chrome_manifest_riesgoso') {
      return `un permiso con alto impacto potencial (${f.detail}).`;
    }
    if (f.discoveryType === 'codigo_ofuscado') {
      return `ofuscación fuerte en el código (${f.detail}); esto no prueba malware por sí solo, pero sí dificulta revisar qué hace la extensión. Minificar nombres para reducir tamaño es normal; ocultar cadenas, reconstruir código o esconder llamadas sensibles es una mala señal.`;
    }
    if (f.discoveryType === 'archivo_minificado') {
      return `código minificado (${f.detail}); esto suele ser normal en extensiones publicadas, pero hace que los hallazgos de esa línea sean más densos y difíciles de revisar manualmente.`;
    }
    if (f.discoveryType === 'correlacion_riesgo') {
      return `una combinación de señales que aumenta el riesgo: ${f.detail}.`;
    }
    return `${f.discoveryType} (${f.detail}).`;
  }

  private humanizeReason(reason: string): string {
    const translations: Array<[RegExp, string]> = [
      [
        /AST taint analysis found sensitive source data reaching a network or messaging sink\./,
        'el análisis de flujo encontró que un dato sensible llega a una salida de red o a mensajería de la extensión.',
      ],
      [
        /The manifest declares a permission that grants sensitive browser or host capability\./,
        'el manifest declara una capacidad sensible del navegador; por sí sola no prueba abuso, pero sirve como contexto.',
      ],
      [
        /The extension declares a Chrome API permission that static analysis did not observe in reachable code\./,
        'el manifest declara un permiso que no vimos usado en código alcanzable.',
      ],
      [
        /Keyboard\/input listeners in content contexts can be used for credential capture\./,
        'los listeners de teclado o formularios en páginas visitadas pueden capturar credenciales si se combinan con envío o persistencia.',
      ],
      [
        /DOM or script injection can modify pages, phish users, or execute attacker-controlled code\./,
        'la inyección de DOM o scripts puede alterar páginas, simular formularios o ejecutar código adicional.',
      ],
      [
        /Cookie access can expose session identifiers\./,
        'las cookies pueden contener identificadores de sesión.',
      ],
      [
        /Browser storage often contains auth tokens, preferences, and application state\./,
        'el almacenamiento del navegador puede contener tokens, preferencias o estado de sesión.',
      ],
      [
        /Multiple suspicious signals co-occur in a way that materially increases malware likelihood\./,
        'varias señales aparecen juntas, lo que aumenta la probabilidad de abuso real.',
      ],
      [
        /The code uses a JavaScript primitive commonly involved in execution, messaging, or exfiltration\./,
        'el código usa una primitiva sensible; se evalúa junto con el rol del archivo, permisos y flujo de datos.',
      ],
      [
        /The code contains obfuscation or aggressive minification signals that reduce auditability\./,
        'el código está escrito o transformado de una forma que reduce la transparencia: puede ser minificación normal, pero si hay cadenas codificadas, nombres artificiales o reconstrucción dinámica de código, la revisión se vuelve menos confiable.',
      ],
      [
        /The file is minified; line numbers are retained, but dense code can hide behavior\./,
        'el archivo está comprimido/minificado; eso puede ser normal para producción, pero concentra mucho comportamiento en pocas líneas y vuelve más difícil explicar cada hallazgo.',
      ],
    ];
    for (const [pattern, replacement] of translations) {
      if (pattern.test(reason)) return reason.replace(pattern, replacement);
    }
    return reason;
  }
}
