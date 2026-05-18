import { Injectable } from '@nestjs/common';
import { StructuredLogger } from '../common/logger/logger.service.js';
import type {
  AnalysisReport,
  AgentAnalysisResult,
  PreprocessorOutput,
  PreprocessingFinding,
  DomainFinding,
  PermisNoUsado,
  UserRiskSummaryItem,
  VerdictedStaticFinding,
  VerdictedDomainFinding,
} from '../common/interfaces/analysis.interfaces.js';
import { UserRiskSummaryService } from './user-risk/user-risk-summary.service.js';

/** Human-readable descriptions for Chrome API permissions, keyed by permission name.
 *  Only permissions that warrant user explanation are included; unknown ones get a generic fallback. */
const PERMISSION_DESCRIPTIONS: Record<string, { categoria: PermisNoUsado['categoria']; descripcion: string }> = {
  // critical
  tabCapture:               { categoria: 'critical', descripcion: 'Capturar el audio y video de cualquier pestaña del navegador en tiempo real.' },
  pageCapture:              { categoria: 'critical', descripcion: 'Guardar páginas web completas (HTML, recursos) como archivos MHTML.' },
  debugger:                 { categoria: 'critical', descripcion: 'Conectarse al protocolo de depuración de Chrome para inspeccionar y modificar cualquier página.' },
  nativeMessaging:          { categoria: 'critical', descripcion: 'Comunicarse con programas instalados en tu computadora fuera del navegador.' },
  proxy:                    { categoria: 'critical', descripcion: 'Redirigir todo el tráfico de red del navegador a través de un servidor externo.' },
  vpnProvider:              { categoria: 'critical', descripcion: 'Crear y controlar conexiones VPN en el navegador.' },
  // high
  cookies:                  { categoria: 'high', descripcion: 'Leer, escribir y eliminar las cookies de cualquier sitio web, incluyendo tokens de sesión.' },
  scripting:                { categoria: 'high', descripcion: 'Inyectar y ejecutar código JavaScript en cualquier página web que visites.' },
  declarativeNetRequest:    { categoria: 'high', descripcion: 'Bloquear, redirigir o modificar las solicitudes de red del navegador.' },
  webRequest:               { categoria: 'high', descripcion: 'Interceptar y observar todas las solicitudes de red en tiempo real.' },
  webRequestBlocking:       { categoria: 'high', descripcion: 'Interceptar y bloquear solicitudes de red antes de que lleguen al servidor.' },
  userScripts:              { categoria: 'high', descripcion: 'Ejecutar scripts de usuario arbitrarios en páginas web.' },
  desktopCapture:           { categoria: 'high', descripcion: 'Capturar la pantalla completa, una ventana o una pestaña como stream de video.' },
  history:                  { categoria: 'high', descripcion: 'Leer y modificar el historial completo de navegación.' },
  downloads:                { categoria: 'high', descripcion: 'Iniciar, cancelar y monitorear todas las descargas del navegador.' },
  'downloads.open':         { categoria: 'high', descripcion: 'Abrir archivos descargados desde el sistema de archivos local.' },
  privacy:                  { categoria: 'high', descripcion: 'Modificar configuraciones de privacidad del navegador como DNT, WebRTC y relleno de formularios.' },
  browsingData:             { categoria: 'high', descripcion: 'Eliminar historial, cookies, caché y otros datos de navegación almacenados.' },
  contentSettings:          { categoria: 'high', descripcion: 'Controlar qué contenido pueden mostrar los sitios (JavaScript, cookies, cámaras, etc.).' },
  webNavigation:            { categoria: 'high', descripcion: 'Monitorear en tiempo real cada navegación que realizas en el navegador.' },
  management:               { categoria: 'high', descripcion: 'Ver, habilitar o deshabilitar otras extensiones instaladas en tu navegador.' },
  // medium
  tabs:                     { categoria: 'medium', descripcion: 'Acceder a las URLs, títulos e íconos de todas las pestañas abiertas.' },
  activeTab:                { categoria: 'medium', descripcion: 'Acceder temporalmente a la pestaña activa cuando el usuario interactúa con la extensión.' },
  bookmarks:                { categoria: 'medium', descripcion: 'Leer, crear y modificar todos tus marcadores guardados.' },
  clipboardRead:            { categoria: 'medium', descripcion: 'Leer el contenido del portapapeles sin que el usuario lo sepa.' },
  clipboardWrite:           { categoria: 'medium', descripcion: 'Escribir contenido en el portapapeles.' },
  geolocation:              { categoria: 'medium', descripcion: 'Conocer tu ubicación geográfica.' },
  notifications:            { categoria: 'medium', descripcion: 'Mostrar notificaciones en tu escritorio.' },
  sessions:                 { categoria: 'medium', descripcion: 'Acceder a las pestañas y ventanas cerradas recientemente.' },
  topSites:                 { categoria: 'medium', descripcion: 'Leer la lista de sitios más visitados del navegador.' },
  // low
  storage:                  { categoria: 'low', descripcion: 'Guardar datos localmente dentro del área de almacenamiento de la extensión.' },
  identity:                 { categoria: 'low', descripcion: 'Obtener tokens de autenticación OAuth para servicios de Google.' },
  alarms:                   { categoria: 'low', descripcion: 'Programar tareas periódicas o temporizadas.' },
  contextMenus:             { categoria: 'low', descripcion: 'Añadir opciones al menú contextual (clic derecho) del navegador.' },
  offscreen:                { categoria: 'low', descripcion: 'Crear documentos fuera de pantalla para procesar contenido en segundo plano.' },
  sidePanel:                { categoria: 'low', descripcion: 'Mostrar una interfaz en el panel lateral del navegador.' },
};

const FILE_TYPE_LABEL: Record<string, string> = {
  content_script: 'content script',
  background: 'background',
  service_worker: 'service worker',
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
  service_worker:
    'Este es el "cerebro" moderno de la extensión (Manifest V3). A diferencia del background tradicional, se despierta solo cuando hay eventos y corre en segundo plano procesando datos y comunicaciones web.',
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
   * Runs the verdict + UserRiskSummary pipeline WITHOUT the agent.
   * Call this BEFORE the LLM agent so the 13 evaluated categories can be
   * included in the agent's evidence bundle. The result is passed back into
   * generateReport() to avoid recomputing the same verdicts twice.
   */
  buildPreAgentSummary(preprocessed: PreprocessorOutput): {
    resultado1: VerdictedStaticFinding[];
    domainFindings: VerdictedDomainFinding[];
    resumenUsuario: UserRiskSummaryItem[];
  } {
    const resultado1 = preprocessed.resultado1.map((f) =>
      this.verdictStatic(f),
    );
    const domainFindings = [
      ...preprocessed.resultado2_priority.map((f) => this.verdictDomain(f)),
      ...preprocessed.resultado2_unknown.map((f) => this.verdictDomain(f)),
    ];
    const resumenUsuario = this.userRiskSummary.buildSummary(
      preprocessed,
      resultado1,
      domainFindings,
    );
    return { resultado1, domainFindings, resumenUsuario };
  }

  /**
   * Builds the final report from the deterministic static-analysis output
   * (resultado1, resultado2_*) and the Agent 1 intent narrative.
   * Verdicts on static findings are derived from each finding's `confidence`
   * (above 0.7 → "positivo").
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
    riskScore?: AnalysisReport['puntuacion_riesgo'],
    preBuilt?: ReturnType<ReportService['buildPreAgentSummary']>,
  ): AnalysisReport {
    // Reuse pre-built verdicts+summary if the processor ran buildPreAgentSummary
    // before the agent; otherwise compute them now (backwards-compat fallback).
    const resultado1 =
      preBuilt?.resultado1 ??
      preprocessed.resultado1.map((f) => this.verdictStatic(f));
    const domainFindings =
      preBuilt?.domainFindings ??
      [
        ...preprocessed.resultado2_priority.map((f) => this.verdictDomain(f)),
        ...preprocessed.resultado2_unknown.map((f) => this.verdictDomain(f)),
      ];
    const resumenUsuario =
      preBuilt?.resumenUsuario ??
      this.userRiskSummary.buildSummary(preprocessed, resultado1, domainFindings);

    const soloPositivos = resultado1.filter((f) => f.veredicto === 'positivo');
    const scoreReal = soloPositivos.reduce(
      (acc, f) => acc + ((f as any).scoreImpact ?? 0),
      0,
    );
    const puntuacionReal =
      scoreReal > 0
        ? {
            score: scoreReal,
            level: (scoreReal >= 50
              ? 'CRITICAL'
              : scoreReal >= 25
                ? 'HIGH'
                : scoreReal >= 10
                  ? 'MEDIUM'
                  : 'LOW') as 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW',
            reasons: riskScore?.reasons ?? [],
          }
        : undefined;
    if (puntuacionReal && agentAnalysis.ranSuccessfully && agentAnalysis.agent1) {
      puntuacionReal.level =
        (
          {
            bajo: 'LOW',
            medio: 'MEDIUM',
            alto: 'HIGH',
            critico: 'CRITICAL',
          } as const
        )[agentAnalysis.agent1.nivel_riesgo_inicial] ?? puntuacionReal.level;
    }
    const agent1 = agentAnalysis.agent1;
    const verdictoDeterministico = this.derivarVerdictoDeterministico(resumenUsuario);
    const veredictoUsuario =
      agentAnalysis.ranSuccessfully && agent1
        ? {
            veredicto: agent1.veredicto_global ?? verdictoDeterministico.veredicto,
            nivel: agent1.nivel_riesgo_inicial ?? verdictoDeterministico.nivel,
            resumen: this.buildVeredictResumen(resumenUsuario),
            razones: verdictoDeterministico.razones,
          }
        : verdictoDeterministico;

    const hallazgosEstaticos = [
      ...this.buildStaticNarratives(
        resultado1.filter((f) => f.veredicto === 'positivo'),
      ),
      ...this.buildDomainNarratives(
        domainFindings.filter((f) => f.veredicto === 'positivo'),
      ),
    ];

    // Split domainFindings back into priority / unknown for the report structure
    const prioritySet = new Set(
      preprocessed.resultado2_priority.map((f) => `${f.domain}:${f.discoveryType}:${f.line}`),
    );
    const resultado2_priority = domainFindings.filter((f) =>
      prioritySet.has(`${f.domain}:${f.discoveryType}:${f.line}`),
    );
    const resultado2_unknown = domainFindings.filter(
      (f) => !prioritySet.has(`${f.domain}:${f.discoveryType}:${f.line}`),
    );

    this.logger.logWithJob(
      jobId,
      'info',
      `Report generated: ${hallazgosEstaticos.length} static findings`,
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
      agente1: agent1,
      resumen_usuario: resumenUsuario,
      veredicto_usuario: veredictoUsuario,
      hallazgos_estaticos_positivos: hallazgosEstaticos,
      permisos_no_usados: this.buildPermisosNoUsados(resultado1, preprocessed),
      estructura: {
        resultado1,
        resultado2_priority,
        resultado2_unknown,
      },
      puntuacion_riesgo: puntuacionReal,
    };
  }

  private buildVeredictResumen(
    resumen: AnalysisReport['resumen_usuario'],
  ): string {
    const criticos = resumen.filter((i) => i.estado === 'critico');
    const sospechosos = resumen.filter((i) => i.estado === 'sospechoso');
    const capacidades = resumen.filter((i) => i.estado === 'capacidad');

    if (criticos.length === 0 && sospechosos.length === 0 && capacidades.length === 0) {
      return 'No se detectaron señales de riesgo significativas en esta extensión.';
    }

    const partes: string[] = [];
    if (criticos.length > 0) {
      partes.push(`${criticos.length} señal(es) crítica(s): ${criticos.map((i) => i.titulo).join(', ')}`);
    }
    if (sospechosos.length > 0) {
      partes.push(`${sospechosos.length} señal(es) sospechosa(s): ${sospechosos.map((i) => i.titulo).join(', ')}`);
    }
    if (capacidades.length > 0) {
      partes.push(`${capacidades.length} capacidad(es) relevante(s): ${capacidades.map((i) => i.titulo).join(', ')}`);
    }
    return `Detectamos ${partes.join('; ')}.`;
  }

  private buildPermisosNoUsados(
    resultado1: VerdictedStaticFinding[],
    preprocessed: PreprocessorOutput,
  ): PermisNoUsado[] {
    // Collect only the permissions that the static-analysis service flagged as
    // "declared but not observed in reachable code". This avoids us re-doing the
    // used/unused computation here; we trust the static-analysis verdict.
    const unusedFindings = resultado1.filter(
      (f) => f.discoveryType === 'permiso_chrome_manifest_no_usado',
    );

    return unusedFindings.map((f): PermisNoUsado => {
      const perm = f.detail; // e.g. "cookies", "history"
      const known = PERMISSION_DESCRIPTIONS[perm];
      // Pull the risk category from the manifest permissionRisk table when
      // available (it already has the authoritative weight classification).
      const riskEntry = preprocessed.manifest.permissionRisk.find(
        (r) => r.permission === perm,
      );
      const categoria: PermisNoUsado['categoria'] =
        riskEntry?.category ?? known?.categoria ?? 'medium';
      const descripcion =
        known?.descripcion ??
        `Permiso "${perm}" declarado en el manifest pero no detectado en el código analizado.`;
      return { permission: perm, categoria, descripcion };
    });
  }

  private derivarVerdictoDeterministico(
    resumen: Parameters<UserRiskSummaryService['buildVerdict']>[0],
  ): ReturnType<UserRiskSummaryService['buildVerdict']> {
    return this.userRiskSummary.buildVerdict(resumen);
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
    if (f.discoveryType === 'flujo_datos_a_red') {
      return `flow:${f.fileType}:${this.flowSourceKind(f.detail)}:${this.flowSinkKind(f.detail)}`;
    }
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

  private flowSourceKind(detail: string): string {
    if (
      /password|credential|token|bearer|cookie|sessionStorage|localStorage|chrome\.storage/i.test(
        detail,
      )
    ) {
      return 'session-or-credential-data';
    }
    if (
      /document\.querySelector|DOM selection|innerText|textContent|document\.body|document\.forms/i.test(
        detail,
      )
    ) {
      return 'page-dom-data';
    }
    return this.normalizeTechnicalDetail(
      detail.split(' viaja hacia ')[0] ?? detail,
    );
  }

  private flowSinkKind(detail: string): string {
    if (
      /fetch|XMLHttpRequest|sendBeacon|WebSocket|axios|servidor en Internet|network sink/i.test(
        detail,
      )
    ) {
      return 'internet-network';
    }
    if (
      /chrome\.runtime\.sendMessage|window\.postMessage|extension message|memoria oculta/i.test(
        detail,
      )
    ) {
      return 'extension-message';
    }
    return this.normalizeTechnicalDetail(
      detail.split(' viaja hacia ')[1] ?? detail,
    );
  }

  private staticNarrativePriority(f: VerdictedStaticFinding): number {
    const typePriority: Partial<Record<string, number>> = {
      flujo_datos_a_red: 100,
      navegacion_externa_sensible: 88,
      correlacion_riesgo: 95,
      interceptacion_api: 94,
      suplantacion_api_navegador: 93,
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

  private describeStaticFinding(f: VerdictedStaticFinding): string {
    const detail = this.normalizeTechnicalDetail(f.detail);
    if (f.discoveryType === 'flujo_datos_a_red') {
      if (
        detail.includes('memoria oculta') ||
        detail.includes('extension message')
      ) {
        return `que la extensión está extrayendo información desde una página o almacenamiento del navegador y pasándola a otro contexto de la extensión (${detail}).`;
      }
      return `que la extensión está enviando información leída desde la página o el navegador hacia una salida de red (${detail}).`;
    }
    if (f.discoveryType === 'navegacion_externa_sensible') {
      return `navegación o enlace externo con contexto sensible (${detail}); puede enviar ASIN, dominio, producto o parámetros de afiliado a un tercero cuando el usuario hace clic.`;
    }
    if (f.discoveryType === 'lectura_cookies') {
      return `acceso a cookies mediante ${detail}; esto puede exponer identificadores de sesión.`;
    }
    if (f.discoveryType === 'lectura_storage_navegador') {
      return `lectura de almacenamiento del navegador mediante ${detail}; ahí pueden existir tokens o estado de sesión.`;
    }
    if (f.discoveryType === 'listener_teclado') {
      return `un listener de entrada/teclado (${detail}); en páginas visitadas puede capturar credenciales o formularios.`;
    }
    if (f.discoveryType === 'inyeccion_dom') {
      return `inyección o modificación de DOM/script (${detail}); esto puede alterar páginas o ejecutar código adicional.`;
    }
    if (f.discoveryType === 'funcion_javascript_riesgosa') {
      if (
        f.detail.includes('sendMessage') ||
        f.detail.includes('postMessage')
      ) {
        return `uso de mensajería (${detail}); puede mover datos desde una página hacia un contexto con más permisos.`;
      }
      return `uso de una función sensible (${detail}); el riesgo depende de los datos que procesa y del destino.`;
    }
    if (f.discoveryType === 'permiso_chrome_manifest_riesgoso') {
      return `un permiso con alto impacto potencial (${detail}).`;
    }
    if (f.discoveryType === 'codigo_ofuscado') {
      return `ofuscación fuerte en el código (${detail}); esto no prueba malware por sí solo, pero sí dificulta revisar qué hace la extensión. Minificar nombres para reducir tamaño es normal; ocultar cadenas, reconstruir código o esconder llamadas sensibles es una mala señal.`;
    }
    if (f.discoveryType === 'archivo_minificado') {
      return `código minificado (${detail}); esto suele ser normal en extensiones publicadas, pero hace que los hallazgos de esa línea sean más densos y difíciles de revisar manualmente.`;
    }
    if (f.discoveryType === 'correlacion_riesgo') {
      return `una combinación de señales que aumenta el riesgo: ${detail}.`;
    }
    if (f.discoveryType === 'interceptacion_api') {
      return `la interceptación o reemplazo de una API nativa del navegador (${detail}); esto es una técnica común para vigilar tráfico interno o alterar el funcionamiento normal.`;
    }
    if (f.discoveryType === 'suplantacion_api_navegador') {
      return `la falsificación de una API del sistema (${detail}); la extensión está intentando engañar a la página web sobre las capacidades, ubicación o identidad del navegador.`;
    }
    return `${f.discoveryType} (${detail}).`;
  }

  private normalizeTechnicalDetail(detail: string): string {
    return detail
      .replace(/(?:\.value){2,}/g, '.value')
      .replace(
        /sensitive API source chrome\.storage\.session\.get\.value/g,
        'datos leídos desde chrome.storage.session',
      )
      .replace(
        /DOM selection via document\.querySelector/g,
        'datos leídos del DOM con document.querySelector',
      )
      .replace(/ viaja hacia /g, ' -> ');
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
