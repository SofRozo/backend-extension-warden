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

const ECOMMERCE_TRACKING_RE =
  /ecommerceEnabled|clickstreamEnabled|advertisementEnabled|ECOMMERCE_TRACK|ECOMMERCE_HEART_BEAT|panalyticsId|DataSharingTypes/i;

const BIS_ADWARE_RE = /bis_data|PANELOS_MESSAGE|posdMessageId|BIS_SEPARATOR/i;

const SHOPIFY_TRACKING_RE =
  /SHOPIFY_DETECTED|ECOMMERCE_INIT_SHOPIFY|globalThis\.Shopify/i;

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
  {
    ruleId: 'privacy.ecommerce_tracking',
    label: 'E-commerce tracking / monetización de navegación',
    id: 'seguimiento_privacidad',
    matches: (finding) => ECOMMERCE_TRACKING_RE.test(finding.detail),
    evidence: (finding) =>
      `Señales de monetización de datos de navegación en ${finding.filePath}:${finding.line}.`,
  },
  {
    ruleId: 'privacy.adware_framework',
    label: 'Framework BIS/PANELOS de inyección de anuncios',
    id: 'seguimiento_privacidad',
    matches: (finding) => BIS_ADWARE_RE.test(finding.detail),
    evidence: (finding) =>
      `Framework de adware BIS/PANELOS detectado en ${finding.filePath}:${finding.line}.`,
  },
  {
    ruleId: 'privacy.shopify_tracking',
    label: 'Detección de tiendas Shopify',
    id: 'seguimiento_privacidad',
    matches: (finding) => SHOPIFY_TRACKING_RE.test(finding.detail),
    evidence: (finding) =>
      `La extensión detecta tiendas Shopify — módulo de tracking de compras en ${finding.filePath}:${finding.line}.`,
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
  const ecommerceTracking = hasDetail(context, ECOMMERCE_TRACKING_RE);
  const bisAdware = hasDetail(context, BIS_ADWARE_RE);
  const shopifyTracking = hasDetail(context, SHOPIFY_TRACKING_RE);
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
    ecommerceTracking ||
    bisAdware ||
    shopifyTracking ||
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
      ? 'La extensión recopila información que te identifica de forma única y la envía a servidores externos — patrón típico de rastreo comercial.'
      : analyticsSignal && networkFlow
        ? 'La extensión envía datos de tu actividad a servicios de análisis o rastreo externos.'
        : sensitiveDomains.length > 0
          ? 'La extensión se comunica con dominios externos que podrían estar relacionados con el rastreo de usuarios.'
          : usesNavigationApi
            ? 'La extensión usa APIs del navegador para observar activamente qué páginas visitas.'
            : hasOnlyDeclaration
              ? 'Tiene permiso para ver tus pestañas, pero no vimos que lo use para rastrearte.'
              : 'No vimos señales de que esta extensión rastree tu actividad.',
    [
      sensitiveDomains.length > 0 &&
        `Se comunica con estos sitios externos: ${sensitiveDomains
          .slice(0, 3)
          .map((d) => d.domain)
          .join(', ')}.`,
      analyticsSignal &&
        'Usa herramientas de análisis de comportamiento (Google Analytics, Mixpanel, Segment u otros).',
      fingerprintSignal &&
        'Recopila características de tu navegador y dispositivo para identificarte de forma única.',
      persistentId &&
        'Crea o usa un identificador único que permite reconocerte entre distintas sesiones.',
      beacon && 'Envía datos de tu actividad al servidor en segundo plano, incluso cuando cierras páginas.',
      context.perms.has('tabs') &&
        !usesNavigationApi &&
        'Tiene permiso para ver tus pestañas, pero no vimos que lo use.',
      context.perms.has('tabs') &&
        usesNavigationApi &&
        'Monitorea activamente las pestañas que tienes abiertas.',
      context.perms.has('webNavigation') &&
        'Puede registrar cada vez que cambias de página.',
      crossSite &&
        'Puede correlacionar tu actividad en múltiples sitios web distintos.',
      hasFinding(context, 'lectura_storage_navegador') &&
        'Guarda información sobre ti de forma persistente en el navegador.',
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
    seguimientoPrivacidadStaticRules,
  );
};
