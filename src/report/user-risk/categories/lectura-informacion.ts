import {
  hasDetail,
  hasFinding,
  makeItem,
  type UserRiskStaticRule,
  type UserRiskCategoryEvaluator,
} from '../types.js';

const SENSITIVE_HOST_RE =
  /mail\.google|gmail|outlook|protonmail|drive\.google|docs\.google|onedrive|dropbox|sharepoint|notion|slack|teams|whatsapp|telegram|messenger|bank|paypal|stripe|metamask|binance|coinbase/i;

const CLIPBOARD_RE =
  /navigator\.clipboard|document\.execCommand\(\s*['"]copy|document\.execCommand\(\s*['"]paste|ClipboardItem|clipboardData/i;
const SELECTION_RE = /window\.getSelection|document\.getSelection|getRangeAt/i;
const IFRAME_CONTENT_RE = /contentDocument|contentWindow|frames\[/i;
const SCREENSHOT_RE =
  /chrome\.tabs\.captureVisibleTab|chrome\.desktopCapture|chrome\.tabCapture|chrome\.pageCapture|getDisplayMedia/i;

export const lecturaInformacionStaticRules: UserRiskStaticRule[] = [
  {
    ruleId: 'read_info.sensitive_flow',
    label: 'Flujo de datos sensibles',
    id: 'lectura_informacion',
    matches: (finding) => finding.discoveryType === 'flujo_datos_a_red',
    evidence: (finding) =>
      `Dato sensible llega a red o mensajería (${finding.filePath}:${finding.line}).`,
  },
  {
    ruleId: 'read_info.cookie_access',
    label: 'Acceso a cookies',
    id: 'lectura_informacion',
    matches: (finding) => finding.discoveryType === 'lectura_cookies',
    evidence: (finding) =>
      `Acceso a cookies de la página en ${finding.filePath}:${finding.line}.`,
  },
  {
    ruleId: 'read_info.browser_storage_access',
    label: 'Lectura de almacenamiento',
    id: 'lectura_informacion',
    matches: (finding) => finding.discoveryType === 'lectura_storage_navegador',
    evidence: (finding) =>
      `Lectura de almacenamiento del navegador en ${finding.filePath}:${finding.line}.`,
  },
  {
    ruleId: 'read_info.input_or_keyboard_listener',
    label: 'Lectura de texto escrito',
    id: 'lectura_informacion',
    matches: (finding) => finding.discoveryType === 'listener_teclado',
    evidence: (finding) =>
      `Puede observar texto escrito por el usuario en ${finding.filePath}:${finding.line}.`,
  },
  {
    ruleId: 'read_info.dom_selectors',
    label: 'Selectores DOM sensibles',
    id: 'lectura_informacion',
    matches: (finding) =>
      /querySelector|getElementById|getElementsByName|document\.body|document\.documentElement|textContent|innerText|\.value/i.test(
        finding.detail,
      ),
    evidence: (finding) =>
      `Puede inspeccionar elementos o texto de página en ${finding.filePath}:${finding.line}.`,
  },
  {
    ruleId: 'read_info.form_data',
    label: 'Lectura de formularios',
    id: 'lectura_informacion',
    matches: (finding) =>
      /document\.forms|HTMLFormElement|FormData|input\[|\.elements\b/i.test(
        finding.detail,
      ),
    evidence: (finding) =>
      `Puede leer contenido de formularios en ${finding.filePath}:${finding.line}.`,
  },
  {
    ruleId: 'read_info.page_message_bridge',
    label: 'Puente de mensajes desde la página',
    id: 'lectura_informacion',
    matches: (finding) =>
      /window\.postMessage|chrome\.runtime\.onMessage|chrome\.runtime\.sendMessage|message sink/i.test(
        finding.detail,
      ),
    evidence: (finding) =>
      `Mensajería puede mover datos leídos entre contextos en ${finding.filePath}:${finding.line}.`,
  },
  {
    ruleId: 'read_info.clipboard_read',
    label: 'Lectura del portapapeles',
    id: 'lectura_informacion',
    matches: (finding) => CLIPBOARD_RE.test(finding.detail),
    evidence: (finding) =>
      `Lee o intercepta el portapapeles en ${finding.filePath}:${finding.line}.`,
  },
  {
    ruleId: 'read_info.selection_api',
    label: 'Lectura de selección del usuario',
    id: 'lectura_informacion',
    matches: (finding) => SELECTION_RE.test(finding.detail),
    evidence: (finding) =>
      `Captura el texto seleccionado por el usuario en ${finding.filePath}:${finding.line}.`,
  },
  {
    ruleId: 'read_info.iframe_content',
    label: 'Lectura de contenido en iframes',
    id: 'lectura_informacion',
    matches: (finding) => IFRAME_CONTENT_RE.test(finding.detail),
    evidence: (finding) =>
      `Accede a contenido dentro de iframes (contentDocument/contentWindow) en ${finding.filePath}:${finding.line}.`,
  },
  {
    ruleId: 'read_info.screenshot_or_capture',
    label: 'Captura de pantalla o pestaña',
    id: 'lectura_informacion',
    matches: (finding) => SCREENSHOT_RE.test(finding.detail),
    evidence: (finding) =>
      `Puede capturar la pantalla o la pestaña visible en ${finding.filePath}:${finding.line}.`,
  },
];

export const evaluateLecturaInformacion: UserRiskCategoryEvaluator = (
  context,
) => {
  const networkFlow = hasFinding(context, 'flujo_datos_a_red');
  const cookieRead = hasFinding(context, 'lectura_cookies');
  const storageRead = hasFinding(context, 'lectura_storage_navegador');
  const formAccess = hasDetail(
    context,
    /document\.forms|FormData|HTMLFormElement|\.elements\b/i,
  );
  const clipboardRead = hasDetail(context, CLIPBOARD_RE);
  const selectionRead = hasDetail(context, SELECTION_RE);
  const screenshot = hasDetail(context, SCREENSHOT_RE);

  // ¿Content script matchea sitios sensibles (correo, drive, banca)?
  const contentMatches =
    context.preprocessed.manifest.contentScripts?.flatMap((cs) => cs.matches) ??
    [];
  const matchesSensitiveSite = contentMatches.some((m) =>
    SENSITIVE_HOST_RE.test(m),
  );

  // Hay uso REAL de DOM/lectura en el código (no solo broadHost declarado)?
  const usesDom = hasDetail(
    context,
    /document\.(body|documentElement|forms|cookie)|querySelector|getElementById|innerText|textContent/i,
  );
  // Inyección programática activa (clave: si inyecta código en páginas, lee
  // todo lo que esas páginas muestran).
  const usesScriptingExecute = context.apiCalls.some((c) =>
    /chrome\.(scripting|tabs)\.executeScript/.test(c.api),
  );

  // Critico: flujo a red, captura de pantalla, o inyección + broadHost.
  const isCritical =
    networkFlow || screenshot || (usesScriptingExecute && context.broadHost);
  // Sospechoso: lectura/captura observada en código (sea via APIs sensibles o
  // matches a sitios sensibles).
  const isSuspicious =
    cookieRead ||
    storageRead ||
    formAccess ||
    clipboardRead ||
    selectionRead ||
    matchesSensitiveSite ||
    usesDom;
  // Capacidad: solo broadHost declarado, sin uso observado de APIs de lectura.
  const hasOnlyDeclaration = context.broadHost && !isSuspicious && !isCritical;

  return makeItem(
    context,
    'lectura_informacion',
    'Lectura de información en páginas',
    isCritical
      ? 'critico'
      : isSuspicious
        ? 'sospechoso'
        : hasOnlyDeclaration
          ? 'capacidad'
          : 'no_detectado',
    networkFlow
      ? 'Vimos datos de página o navegador llegando a una salida de red o mensajería.'
      : screenshot
        ? 'La extensión puede capturar imágenes de la pantalla o la pestaña visible.'
        : usesScriptingExecute && context.broadHost
          ? 'La extensión inyecta scripts en cada página visitada — esos scripts pueden leer todo el DOM del sitio donde se ejecutan.'
          : isSuspicious
            ? 'La extensión puede leer cosas como cookies, almacenamiento, formularios, portapapeles o selección del usuario.'
            : hasOnlyDeclaration
              ? 'La extensión declara host_permissions amplios pero su código no parece leer DOM ni datos del usuario.'
              : 'No vimos señales fuertes de lectura de contenido de páginas.',
    [
      networkFlow && 'Flujo de datos sensible detectado.',
      context.broadHost &&
        !isSuspicious &&
        !isCritical &&
        'Permisos amplios de host declarados (sin lectura observada en código).',
      usesScriptingExecute &&
        'Inyecta scripts en páginas con chrome.scripting.executeScript: lo inyectado puede leer todo el DOM.',
      usesDom &&
        'El código lee elementos del DOM (document.body/forms/cookie, querySelector, innerText).',
      cookieRead && 'Lectura de cookies detectada.',
      storageRead && 'Lectura de localStorage/sessionStorage/chrome.storage.',
      formAccess && 'Lee elementos de formularios (FormData / document.forms).',
      clipboardRead && 'Lee el portapapeles del usuario.',
      selectionRead && 'Captura el texto seleccionado por el usuario.',
      screenshot && 'Puede capturar la pantalla o la pestaña visible.',
      matchesSensitiveSite &&
        'Sus content scripts apuntan a sitios sensibles (correo, drive, banca, mensajería).',
      hasDetail(context, IFRAME_CONTENT_RE) &&
        'Accede a contenido dentro de iframes embebidos.',
    ],
    [
      '¿Puede leer texto dentro de páginas web?',
      '¿Puede leer mensajes, correos o documentos abiertos en el navegador?',
      '¿Puede leer contenido escrito en formularios?',
      '¿Puede inspeccionar información sensible mostrada en pantalla?',
      '¿Puede acceder al DOM completo de una página?',
    ],
  );
};
