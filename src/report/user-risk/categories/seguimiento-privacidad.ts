import {
  hasApiCall,
  hasDetail,
  hasFinding,
  makeItem,
  type UserRiskStaticRule,
  type UserRiskCategoryEvaluator,
} from '../types.js';

const NAV_OBSERVE_RE =
  /^chrome\.(tabs\.(query|get|onActivated|onUpdated|onCreated|onRemoved)|webNavigation\.|history\.)/;

const ANALYTICS_RE =
  /analytics|telemetry|tracking|segment|mixpanel|amplitude|ga\(|gtag|pixel|fingerprint|clientId|userId|deviceId|google-analytics|googletagmanager|hotjar|posthog|fullstory|matomo|piwik|heap\.io|kissmetrics|fbq\(|fbevents|doubleclick/i;
const FINGERPRINT_RE =
  /canvas\.toDataURL|getImageData\b|getContext\(['"]webgl|WebGLRenderingContext|AudioContext|OfflineAudioContext|navigator\.hardwareConcurrency|navigator\.deviceMemory|navigator\.platform|navigator\.userAgent|navigator\.languages|navigator\.plugins|screen\.colorDepth|screen\.pixelDepth|screen\.width|screen\.height|Intl\.DateTimeFormat\(\)\.resolvedOptions|MediaDevices\.enumerateDevices/i;
const PERSISTENT_ID_RE =
  /crypto\.randomUUID|generateUUID|uuid\(|v4\(\)|deviceId|clientId|installId|machineId|fingerprintjs|FingerprintJS|client_id\b|device_id\b|install_id\b/i;
const REFERRER_RE = /document\.referrer|navigator\.sendBeacon|Beacon API/i;

export const seguimientoPrivacidadStaticRules: UserRiskStaticRule[] = [
  {
    ruleId: 'privacy.data_flow',
    label: 'Movimiento/envío de datos',
    id: 'seguimiento_privacidad',
    matches: (finding) => finding.discoveryType === 'flujo_datos_a_red',
    evidence: (finding) =>
      `Hay envío o movimiento de datos detectado (${finding.filePath}:${finding.line}).`,
  },
  {
    ruleId: 'privacy.storage_access',
    label: 'Acceso a datos persistidos',
    id: 'seguimiento_privacidad',
    matches: (finding) => finding.discoveryType === 'lectura_storage_navegador',
    evidence: (finding) =>
      `Acceso a datos persistidos del usuario en ${finding.filePath}:${finding.line}.`,
  },
  {
    ruleId: 'privacy.message_bridge',
    label: 'Mensajería entre contextos',
    id: 'seguimiento_privacidad',
    matches: (finding) =>
      finding.discoveryType === 'funcion_javascript_riesgosa' &&
      /sendMessage|postMessage/i.test(finding.detail),
    evidence: (finding) =>
      `Mensajería interna puede mover datos entre contextos en ${finding.filePath}:${finding.line}.`,
  },
  {
    ruleId: 'privacy.network_correlation',
    label: 'Correlación con red',
    id: 'seguimiento_privacidad',
    matches: (finding) =>
      finding.discoveryType === 'correlacion_riesgo' &&
      /network|domain|fetch|sendbeacon|websocket/i.test(finding.detail),
    evidence: (finding) =>
      `Combinación con envío/contacto de red en ${finding.filePath}:${finding.line}.`,
  },
  {
    ruleId: 'privacy.analytics_or_tracking',
    label: 'Analytics o tracking',
    id: 'seguimiento_privacidad',
    matches: (finding) => ANALYTICS_RE.test(finding.detail),
    evidence: (finding) =>
      `Señal de analítica, identificadores o tracking en ${finding.filePath}:${finding.line}.`,
  },
  {
    ruleId: 'privacy.fingerprinting',
    label: 'Huella digital del navegador',
    id: 'seguimiento_privacidad',
    matches: (finding) => FINGERPRINT_RE.test(finding.detail),
    evidence: (finding) =>
      `Lectura de APIs típicas de fingerprinting (canvas, WebGL, audio, navigator, screen) en ${finding.filePath}:${finding.line}.`,
  },
  {
    ruleId: 'privacy.persistent_identifier',
    label: 'Identificador persistente',
    id: 'seguimiento_privacidad',
    matches: (finding) => PERSISTENT_ID_RE.test(finding.detail),
    evidence: (finding) =>
      `Genera o referencia un identificador persistente (UUID, clientId, deviceId) en ${finding.filePath}:${finding.line}.`,
  },
  {
    ruleId: 'privacy.beacon_or_referrer',
    label: 'Beacon o referrer',
    id: 'seguimiento_privacidad',
    matches: (finding) => REFERRER_RE.test(finding.detail),
    evidence: (finding) =>
      `Usa navigator.sendBeacon o lee document.referrer en ${finding.filePath}:${finding.line}.`,
  },
  {
    ruleId: 'privacy.browsing_activity_api',
    label: 'APIs de actividad de navegación',
    id: 'seguimiento_privacidad',
    matches: (finding) =>
      /chrome\.tabs|chrome\.history|chrome\.webNavigation|chrome\.webRequest|chrome\.cookies/i.test(
        finding.detail,
      ),
    evidence: (finding) =>
      `Usa APIs que pueden revelar navegación o actividad en ${finding.filePath}:${finding.line}.`,
  },
];

export const evaluateSeguimientoPrivacidad: UserRiskCategoryEvaluator = (
  context,
) => {
  const sensitiveDomains = context.domainFindings.filter(
    (d) => d.veredicto === 'positivo' && d.discoveryType === 'url_en_codigo',
  );
  const hasNavigationPerm =
    context.perms.has('tabs') || context.perms.has('webNavigation');
  // USO REAL de las APIs de navegación (no solo permiso declarado).
  const usesNavigationApi = hasApiCall(context, NAV_OBSERVE_RE);
  const analyticsSignal = hasDetail(context, ANALYTICS_RE);
  const fingerprintSignal = hasDetail(context, FINGERPRINT_RE);
  const persistentId = hasDetail(context, PERSISTENT_ID_RE);
  const beacon = hasDetail(context, REFERRER_RE);
  const networkFlow = hasFinding(context, 'flujo_datos_a_red');
  const crossSite = context.broadHost;

  // Critico: fingerprinting + envío a red, o broadHost + analytics + flow
  const isCritical =
    (fingerprintSignal && networkFlow) ||
    (crossSite && analyticsSignal && networkFlow);
  // Sospechoso: señales REALES en código (fingerprint/analytics/persistent ID/beacon)
  // o uso ACTIVO de APIs de navegación, o dominios sensibles.
  const isSuspicious =
    analyticsSignal ||
    fingerprintSignal ||
    persistentId ||
    beacon ||
    sensitiveDomains.length > 0 ||
    usesNavigationApi;
  // Capacidad: solo permiso declarado, sin uso real.
  const hasOnlyDeclaration = hasNavigationPerm && !usesNavigationApi;

  return makeItem(
    context,
    'seguimiento_privacidad',
    'Seguimiento y privacidad',
    isCritical
      ? 'critico'
      : isSuspicious
        ? 'sospechoso'
        : hasOnlyDeclaration
          ? 'capacidad'
          : 'no_detectado',
    isCritical
      ? 'La extensión combina recolección de identificadores/fingerprint con envío a red. Es el patrón típico de tracking comercial agresivo.'
      : analyticsSignal && networkFlow
        ? 'La extensión contacta servicios de analítica/tracking conocidos.'
        : sensitiveDomains.length > 0
          ? 'La extensión contacta dominios sensibles o de terceros relevantes para privacidad.'
          : usesNavigationApi
            ? 'La extensión usa activamente APIs de navegación (tabs/webNavigation/history) para observar lo que haces.'
            : hasOnlyDeclaration
              ? 'Declara permiso tabs/webNavigation pero su código no parece usarlo.'
              : 'No vimos señales fuertes de rastreo.',
    [
      sensitiveDomains.length > 0 &&
        `Dominios sensibles contactados: ${sensitiveDomains
          .slice(0, 3)
          .map((d) => d.domain)
          .join(', ')}.`,
      analyticsSignal &&
        'Referencias a librerías o endpoints de analytics/tracking (GA, GTM, Mixpanel, Segment, etc.).',
      fingerprintSignal &&
        'Lee APIs de fingerprint del navegador (canvas, WebGL, AudioContext, navigator, screen).',
      persistentId &&
        'Genera o referencia identificadores persistentes (UUID, clientId, deviceId).',
      beacon && 'Usa navigator.sendBeacon o lee document.referrer.',
      context.perms.has('tabs') &&
        !usesNavigationApi &&
        'Permiso tabs declarado (sin uso observado).',
      context.perms.has('tabs') &&
        usesNavigationApi &&
        'Permiso tabs USADO en código (observa pestañas activamente).',
      context.perms.has('webNavigation') &&
        'Permiso webNavigation: observa transiciones entre páginas.',
      crossSite &&
        'Acceso amplio a sitios: puede correlacionar entre dominios.',
      hasFinding(context, 'lectura_storage_navegador') &&
        'Lectura de almacenamiento para persistir información.',
    ],
    [
      '¿Rastrea mi actividad de navegación?',
      '¿Crea perfiles sobre mis hábitos?',
      '¿Comparte mis datos con terceros?',
      '¿Recolecta métricas de uso?',
      '¿Utiliza analytics ocultos?',
      '¿Almacena identificadores persistentes?',
      '¿Puede seguirme entre múltiples sitios web?',
    ],
  );
};
