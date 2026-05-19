import {
  hasDetail,
  hasFinding,
  makeItem,
  type UserRiskCategoryEvaluator,
  type UserRiskStaticRule,
} from '../types.js';

const HISTORY_API_RE =
  /chrome\.history\.search|chrome\.history\.getVisits|chrome\.history\.addUrl|chrome\.history\.deleteUrl|chrome\.history\.deleteRange|chrome\.history\b/i;
const TABS_NAV_RE =
  /chrome\.tabs\.query|chrome\.tabs\.get\b|chrome\.tabs\.onUpdated|chrome\.tabs\.onActivated|chrome\.tabs\.onCreated|chrome\.tabs\.onRemoved/i;
const WEBNAV_RE =
  /chrome\.webNavigation|onBeforeNavigate|onCommitted|onCompleted|onHistoryStateUpdated|onReferenceFragmentUpdated/i;
const BOOKMARKS_RE = /chrome\.bookmarks|chrome\.topSites|chrome\.sessions/i;
const URL_FLOW_RE =
  /tab\.url|tab\.title|url|history|webNavigation|title|location\.href/i;

export const accesoHistorialStaticRules: UserRiskStaticRule[] = [
  {
    ruleId: 'history.permission_history_or_tabs',
    label: 'Permiso history/tabs',
    id: 'acceso_historial',
    matches: (finding) =>
      finding.discoveryType === 'permiso_chrome_manifest_riesgoso' &&
      /history|tabs|webNavigation|bookmarks|topSites|sessions/i.test(
        finding.detail,
      ),
    evidence: (finding) =>
      `Permiso relacionado con historial/pestañas/marcadores en ${finding.filePath}:${finding.line}.`,
  },
  {
    ruleId: 'history.history_api_usage',
    label: 'Uso de API de historial',
    id: 'acceso_historial',
    matches: (finding) => HISTORY_API_RE.test(finding.detail),
    evidence: (finding) =>
      `Usa chrome.history (puede revelar historial completo) en ${finding.filePath}:${finding.line}.`,
  },
  {
    ruleId: 'history.tabs_navigation_events',
    label: 'Eventos de pestañas',
    id: 'acceso_historial',
    matches: (finding) => TABS_NAV_RE.test(finding.detail),
    evidence: (finding) =>
      `Escucha eventos de pestañas (onUpdated/onActivated): puede ver cada página que visitas en ${finding.filePath}:${finding.line}.`,
  },
  {
    ruleId: 'history.webnavigation_listener',
    label: 'Listener de webNavigation',
    id: 'acceso_historial',
    matches: (finding) => WEBNAV_RE.test(finding.detail),
    evidence: (finding) =>
      `Escucha chrome.webNavigation: ve todas las transiciones entre páginas en ${finding.filePath}:${finding.line}.`,
  },
  {
    ruleId: 'history.bookmarks_top_sessions',
    label: 'Marcadores, top sites o sesiones',
    id: 'acceso_historial',
    matches: (finding) => BOOKMARKS_RE.test(finding.detail),
    evidence: (finding) =>
      `Lee marcadores, sitios más visitados o sesiones recientes en ${finding.filePath}:${finding.line}.`,
  },
  {
    ruleId: 'history.url_transmission',
    label: 'URL de navegación en flujo',
    id: 'acceso_historial',
    matches: (finding) =>
      finding.discoveryType === 'flujo_datos_a_red' &&
      URL_FLOW_RE.test(finding.detail),
    evidence: (finding) =>
      `URL/título/historial aparece en flujo de datos en ${finding.filePath}:${finding.line}.`,
  },
];

export const evaluateAccesoHistorial: UserRiskCategoryEvaluator = (context) => {
  const { perms } = context;
  const historyApi = hasDetail(context, HISTORY_API_RE);
  const tabsListener = hasDetail(context, TABS_NAV_RE);
  const webNavListener = hasDetail(context, WEBNAV_RE);
  const bookmarksApi = hasDetail(context, BOOKMARKS_RE);
  const urlFlow =
    hasFinding(context, 'flujo_datos_a_red') &&
    context.positives.some(
      (f) =>
        f.discoveryType === 'flujo_datos_a_red' && URL_FLOW_RE.test(f.detail),
    );

  // Critico: leer historial Y enviarlo, o webNavigation listener + flow
  const isCritical = (historyApi && urlFlow) || (webNavListener && urlFlow);
  // Sospechoso: permiso history activo o uso real de la API
  const isSuspicious =
    perms.has('history') ||
    historyApi ||
    webNavListener ||
    bookmarksApi ||
    tabsListener;

  return makeItem(
    context,
    'acceso_historial',
    'Historial de navegación',
    isCritical
      ? 'critico'
      : isSuspicious
        ? 'sospechoso'
        : perms.has('tabs')
          ? 'capacidad'
          : 'no_detectado',
    isCritical
      ? 'La extensión lee tu historial de navegación o las páginas que visitas y los envía a un servidor externo.'
      : perms.has('history') || historyApi
        ? 'Puede acceder a tu historial completo de navegación.'
        : webNavListener || tabsListener
          ? 'Puede ver cada página que visitas en tiempo real mientras navegas.'
          : perms.has('tabs')
            ? 'Puede ver la dirección y el título de las pestañas que tienes abiertas.'
            : 'No vimos que esta extensión acceda a tu historial de navegación.',
    [
      perms.has('history') &&
        'Tiene permiso para leer tu historial de navegación.',
      perms.has('tabs') && 'Tiene permiso para ver tus pestañas abiertas.',
      perms.has('webNavigation') &&
        'Tiene permiso para rastrear cada cambio de página.',
      perms.has('bookmarks') && 'Tiene permiso para leer tus marcadores.',
      perms.has('topSites') &&
        'Tiene permiso para ver los sitios que más visitas.',
      perms.has('sessions') &&
        'Tiene permiso para ver sesiones recientes del navegador.',
      historyApi && 'Consulta activamente tu historial de navegación.',
      tabsListener &&
        'Se entera en tiempo real de cada página que abres o visitas.',
      webNavListener && 'Registra cada vez que cambias de página o URL.',
      bookmarksApi &&
        'Lee tus marcadores, sitios favoritos o sesiones recientes.',
      urlFlow &&
        'Las páginas que visitas o sus títulos viajan hacia servidores externos.',
    ],
    [
      '¿Puede leer mi historial de navegación?',
      '¿Almacena o transmite las páginas que visito?',
      '¿Analiza patrones de comportamiento basados en historial?',
    ],
    accesoHistorialStaticRules,
  );
};
