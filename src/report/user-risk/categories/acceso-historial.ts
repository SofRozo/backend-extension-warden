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
const URL_FLOW_RE = /tab\.url|tab\.title|url|history|webNavigation|title|location\.href/i;

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
  const isCritical =
    (historyApi && urlFlow) || (webNavListener && urlFlow);
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
      ? 'La extensión lee historial/transiciones de navegación y los envía hacia una salida de red.'
      : perms.has('history') || historyApi
        ? 'Puede leer historial de navegación.'
        : webNavListener || tabsListener
          ? 'Puede observar cada página que visitas escuchando eventos de pestañas/navegación.'
          : perms.has('tabs')
            ? 'Puede ver URLs y títulos de pestañas abiertas, aunque no necesariamente todo el historial.'
            : 'No vimos permiso directo de historial.',
    [
      perms.has('history') && 'Permiso history.',
      perms.has('tabs') && 'Permiso tabs.',
      perms.has('webNavigation') && 'Permiso webNavigation.',
      perms.has('bookmarks') && 'Permiso bookmarks.',
      perms.has('topSites') && 'Permiso topSites.',
      perms.has('sessions') && 'Permiso sessions.',
      historyApi && 'Llama a chrome.history.search/getVisits.',
      tabsListener &&
        'Escucha eventos de pestañas (onUpdated/onActivated): cada navegación es visible.',
      webNavListener &&
        'Escucha chrome.webNavigation: registra cada transición de URL.',
      bookmarksApi && 'Lee marcadores, top sites o sesiones recientes.',
      urlFlow && 'URLs/títulos fluyen hacia una salida de red.',
    ],
    [
      '¿Puede leer mi historial de navegación?',
      '¿Almacena o transmite las páginas que visito?',
      '¿Analiza patrones de comportamiento basados en historial?',
    ],
  );
};
