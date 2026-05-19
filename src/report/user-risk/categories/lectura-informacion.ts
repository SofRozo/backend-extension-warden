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
      `Información leída de la página viaja hacia un servidor externo (${finding.filePath}:${finding.line}).`,
  },
  {
    ruleId: 'read_info.cookie_access',
    label: 'Acceso a cookies',
    id: 'lectura_informacion',
    matches: (finding) => finding.discoveryType === 'lectura_cookies',
    evidence: (finding) =>
      `Puede leer las cookies del sitio que estás visitando — ahí se guardan tus sesiones activas (${finding.filePath}:${finding.line}).`,
  },
  {
    ruleId: 'read_info.browser_storage_access',
    label: 'Lectura de almacenamiento',
    id: 'lectura_informacion',
    matches: (finding) => finding.discoveryType === 'lectura_storage_navegador',
    evidence: (finding) =>
      `Accede al almacenamiento local del navegador, donde los sitios guardan datos de tu sesión (${finding.filePath}:${finding.line}).`,
  },
  {
    ruleId: 'read_info.input_or_keyboard_listener',
    label: 'Lectura de texto escrito',
    id: 'lectura_informacion',
    matches: (finding) => finding.discoveryType === 'listener_teclado',
    evidence: (finding) =>
      `Puede observar lo que escribes en el teclado mientras navegas (${finding.filePath}:${finding.line}).`,
  },
  {
    ruleId: 'read_info.dom_selectors',
    label: 'Lectura del contenido visible de la página',
    id: 'lectura_informacion',
    matches: (finding) =>
      /querySelector|getElementById|getElementsByName|document\.body|document\.documentElement|textContent|innerText|\.value/i.test(
        finding.detail,
      ),
    evidence: (finding) =>
      `Puede leer el texto y contenido visible de las páginas que visitas (${finding.filePath}:${finding.line}).`,
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
      `Puede leer lo que escribes en formularios web, incluyendo campos de login (${finding.filePath}:${finding.line}).`,
  },
  {
    ruleId: 'read_info.page_message_bridge',
    label: 'Datos internos que se mueven entre partes de la extensión',
    id: 'lectura_informacion',
    matches: (finding) =>
      /window\.postMessage|chrome\.runtime\.onMessage|chrome\.runtime\.sendMessage|message sink/i.test(
        finding.detail,
      ),
    evidence: (finding) =>
      `Información leída de la página se transfiere hacia otras partes de la extensión con más permisos (${finding.filePath}:${finding.line}).`,
  },
  {
    ruleId: 'read_info.clipboard_read',
    label: 'Lectura del portapapeles',
    id: 'lectura_informacion',
    matches: (finding) => CLIPBOARD_RE.test(finding.detail),
    evidence: (finding) =>
      `Puede acceder a lo que tienes copiado en el portapapeles (Ctrl+C) (${finding.filePath}:${finding.line}).`,
  },
  {
    ruleId: 'read_info.selection_api',
    label: 'Lectura de texto seleccionado',
    id: 'lectura_informacion',
    matches: (finding) => SELECTION_RE.test(finding.detail),
    evidence: (finding) =>
      `Puede leer el texto que seleccionas con el cursor en cualquier página (${finding.filePath}:${finding.line}).`,
  },
  {
    ruleId: 'read_info.iframe_content',
    label: 'Lectura de contenido en marcos incrustados',
    id: 'lectura_informacion',
    matches: (finding) => IFRAME_CONTENT_RE.test(finding.detail),
    evidence: (finding) =>
      `Puede acceder al contenido de partes de la página cargadas desde otros sitios (marcos incrustados) (${finding.filePath}:${finding.line}).`,
  },
  {
    ruleId: 'read_info.screenshot_or_capture',
    label: 'Captura de pantalla',
    id: 'lectura_informacion',
    matches: (finding) => SCREENSHOT_RE.test(finding.detail),
    evidence: (finding) =>
      `Puede tomar capturas de pantalla de lo que ves en el navegador sin que lo notes (${finding.filePath}:${finding.line}).`,
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
      ? 'Detectamos que la extensión lee información de las páginas que visitas y la envía a un servidor externo.'
      : screenshot
        ? 'La extensión puede tomar capturas de pantalla de tu navegador sin que lo veas.'
        : usesScriptingExecute && context.broadHost
          ? 'La extensión inserta código propio dentro de cada página que visitas, lo que le permite leer todo su contenido.'
          : isSuspicious
            ? 'La extensión puede leer datos de las páginas: cookies de sesión, formularios, portapapeles o texto seleccionado.'
            : hasOnlyDeclaration
              ? 'La extensión declara acceso amplio a sitios web, pero no vimos que lo use para leer datos de los usuarios.'
              : 'No vimos señales de que esta extensión lea contenido de tus páginas.',
    [
      networkFlow &&
        'Información leída de páginas viaja hacia servidores externos.',
      context.broadHost &&
        !isSuspicious &&
        !isCritical &&
        'Tiene permiso para acceder a todos los sitios web, aunque no vimos que lea datos.',
      usesScriptingExecute &&
        'Inserta código propio dentro de las páginas que visitas — ese código puede leer todo lo que hay en ellas.',
      usesDom &&
        'Lee el contenido visible de las páginas (textos, formularios, elementos de la página).',
      cookieRead &&
        'Accede a las cookies del sitio — ahí se guardan tus sesiones activas.',
      storageRead &&
        'Lee datos guardados localmente en el navegador por los sitios que visitas.',
      formAccess && 'Puede leer el contenido de formularios web.',
      clipboardRead && 'Puede leer lo que tienes copiado en el portapapeles.',
      selectionRead && 'Puede leer el texto que seleccionas con el cursor.',
      screenshot && 'Puede tomar capturas de pantalla de lo que ves.',
      matchesSensitiveSite &&
        'Está configurada para ejecutarse en sitios sensibles como correo, banca o redes sociales.',
      hasDetail(context, IFRAME_CONTENT_RE) &&
        'Puede acceder a secciones de páginas cargadas desde otros dominios (marcos incrustados).',
    ],
    [
      '¿Puede leer texto dentro de páginas web?',
      '¿Puede leer mensajes, correos o documentos abiertos en el navegador?',
      '¿Puede leer contenido escrito en formularios?',
      '¿Puede inspeccionar información sensible mostrada en pantalla?',
      '¿Puede acceder al contenido completo de una página?',
    ],
    lecturaInformacionStaticRules,
  );
};
