import {
  hasDetail,
  makeItem,
  type UserRiskCategoryEvaluator,
  type UserRiskStaticRule,
} from '../types.js';

const REQUEST_INTERCEPT_RE =
  /chrome\.webRequest|onBeforeRequest|onBeforeSendHeaders|onHeadersReceived|onResponseStarted|onBeforeRedirect|onAuthRequired|blocking|requestHeaders|responseHeaders/i;
const DNR_API_RE =
  /chrome\.declarativeNetRequest|updateDynamicRules|updateSessionRules|updateEnabledRulesets|getDynamicRules/i;
const HEADER_REWRITE_RE =
  /modifyHeaders|setRequestHeader|removeHeader|setResponseHeader|Authorization|Cookie|Referer|Origin/i;
const REDIRECT_RE = /redirect|upgradeScheme|window\.location|location\.replace|location\.assign/i;
const PROXY_RE = /chrome\.proxy|vpnProvider|ProxyConfig|PacScript|FixedServers/i;
const DOWNLOAD_INTERCEPT_RE =
  /chrome\.downloads\.onDeterminingFilename|chrome\.downloads\.onCreated|chrome\.downloads\.onChanged/i;

export const manipulacionTraficoStaticRules: UserRiskStaticRule[] = [
  {
    ruleId: 'traffic.correlation_rewrite',
    label: 'Correlación de tráfico/redirección',
    id: 'manipulacion_trafico',
    matches: (finding) =>
      finding.discoveryType === 'correlacion_riesgo' &&
      /webrequest|traffic|redirect|proxy|declarativenetrequest/i.test(
        finding.detail,
      ),
    evidence: (finding) =>
      `Combinación relacionada con tráfico o redirección en ${finding.filePath}:${finding.line}.`,
  },
  {
    ruleId: 'traffic.permission_network_control',
    label: 'Permiso de control de red',
    id: 'manipulacion_trafico',
    matches: (finding) =>
      finding.discoveryType === 'permiso_chrome_manifest_riesgoso' &&
      /webRequest|webRequestBlocking|declarativeNetRequest|proxy/i.test(
        finding.detail,
      ),
    evidence: (finding) =>
      `Permiso de red/tráfico detectado en ${finding.filePath}:${finding.line}.`,
  },
  {
    ruleId: 'traffic.request_interception_api',
    label: 'Intercepción de solicitudes',
    id: 'manipulacion_trafico',
    matches: (finding) => REQUEST_INTERCEPT_RE.test(finding.detail),
    evidence: (finding) =>
      `Puede observar o alterar solicitudes HTTP en ${finding.filePath}:${finding.line}.`,
  },
  {
    ruleId: 'traffic.dnr_redirect_or_modify',
    label: 'Reglas DNR de bloqueo/redirección/modificación',
    id: 'manipulacion_trafico',
    matches: (finding) =>
      DNR_API_RE.test(finding.detail) ||
      /modifyHeaders|redirect|block|upgradeScheme/i.test(finding.detail),
    evidence: (finding) =>
      `Regla o API puede bloquear, redirigir o modificar recursos en ${finding.filePath}:${finding.line}.`,
  },
  {
    ruleId: 'traffic.dynamic_dnr_rules',
    label: 'Modificación de reglas DNR en tiempo de ejecución',
    id: 'manipulacion_trafico',
    matches: (finding) =>
      /updateDynamicRules|updateSessionRules|updateEnabledRulesets/i.test(
        finding.detail,
      ),
    evidence: (finding) =>
      `Cambia reglas de red en tiempo de ejecución (lo que aplica una vez instalada puede no parecerse a lo declarado) en ${finding.filePath}:${finding.line}.`,
  },
  {
    ruleId: 'traffic.header_rewrite',
    label: 'Reescritura de cabeceras HTTP',
    id: 'manipulacion_trafico',
    matches: (finding) => HEADER_REWRITE_RE.test(finding.detail),
    evidence: (finding) =>
      `Manipula cabeceras de petición/respuesta (Authorization, Cookie, Referer...) en ${finding.filePath}:${finding.line}.`,
  },
  {
    ruleId: 'traffic.redirect_pattern',
    label: 'Redirección directa de navegación',
    id: 'manipulacion_trafico',
    matches: (finding) => REDIRECT_RE.test(finding.detail),
    evidence: (finding) =>
      `Redirige la navegación del usuario en ${finding.filePath}:${finding.line}.`,
  },
  {
    ruleId: 'traffic.download_interception',
    label: 'Intercepción de descargas',
    id: 'manipulacion_trafico',
    matches: (finding) => DOWNLOAD_INTERCEPT_RE.test(finding.detail),
    evidence: (finding) =>
      `Intercepta o renombra descargas (chrome.downloads.onDeterminingFilename/onCreated) en ${finding.filePath}:${finding.line}.`,
  },
  {
    ruleId: 'traffic.proxy_or_vpn',
    label: 'Proxy/VPN',
    id: 'manipulacion_trafico',
    matches: (finding) => PROXY_RE.test(finding.detail),
    evidence: (finding) =>
      `Puede influir en proxy/VPN o ruta de tráfico en ${finding.filePath}:${finding.line}.`,
  },
];

export const evaluateManipulacionTrafico: UserRiskCategoryEvaluator = (
  context,
) => {
  const { perms } = context;
  const hasTrafficPermission =
    perms.has('proxy') ||
    perms.has('webRequest') ||
    perms.has('webRequestBlocking') ||
    perms.has('declarativeNetRequest') ||
    perms.has('declarativeNetRequestWithHostAccess');

  const dynamicRules = hasDetail(
    context,
    /updateDynamicRules|updateSessionRules|updateEnabledRulesets/i,
  );
  const headerRewrite = hasDetail(context, HEADER_REWRITE_RE);
  const redirect = hasDetail(context, REDIRECT_RE);
  const downloadIntercept = hasDetail(context, DOWNLOAD_INTERCEPT_RE);

  // Critico: proxy/webRequestBlocking, o reglas dinámicas + headers reescritos
  const isCritical =
    perms.has('proxy') ||
    perms.has('webRequestBlocking') ||
    (dynamicRules && headerRewrite);

  return makeItem(
    context,
    'manipulacion_trafico',
    'Manipulación de tráfico',
    isCritical
      ? 'critico'
      : perms.has('webRequest') ||
          perms.has('declarativeNetRequest') ||
          headerRewrite ||
          downloadIntercept
        ? 'capacidad'
        : 'no_detectado',
    isCritical
      ? 'La extensión puede interceptar, bloquear o redirigir todo el tráfico del navegador. Es una capacidad de altísimo impacto.'
      : hasTrafficPermission
        ? 'La extensión puede observar, bloquear, redirigir o modificar solicitudes según sus permisos.'
        : 'No vimos permisos fuertes de manipulación de tráfico.',
    [
      perms.has('proxy') && 'Permiso proxy.',
      perms.has('webRequest') && 'Permiso webRequest.',
      perms.has('webRequestBlocking') && 'Permiso webRequestBlocking.',
      perms.has('declarativeNetRequest') && 'Permiso declarativeNetRequest.',
      perms.has('declarativeNetRequestWithHostAccess') &&
        'Permiso declarativeNetRequestWithHostAccess.',
      dynamicRules &&
        'Crea/actualiza reglas DNR en runtime (lo declarado en el manifest puede no ser lo aplicado).',
      headerRewrite &&
        'Reescribe cabeceras HTTP (Authorization, Cookie, Referer...).',
      redirect && 'Redirige la navegación a otras URLs.',
      downloadIntercept &&
        'Intercepta o renombra descargas en curso (chrome.downloads.onDeterminingFilename).',
    ],
    [
      '¿Puede interceptar solicitudes web?',
      '¿Puede modificar respuestas HTTP?',
      '¿Puede redirigirme a otras páginas?',
      '¿Puede alterar descargas o recursos cargados?',
    ],
  );
};
