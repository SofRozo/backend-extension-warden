import {
  findApiCall,
  hasApiCall,
  hasDetail,
  hasFinding,
  makeItem,
  type UserRiskStaticRule,
  type UserRiskCategoryEvaluator,
} from '../types.js';

const SCRIPTING_EXECUTE_RE =
  /^chrome\.(scripting\.executeScript|tabs\.executeScript|scripting\.insertCSS|tabs\.insertCSS)/;

// Patrones de detección
const OVERLAY_RE =
  /position\s*[:=]\s*['"]?(fixed|absolute)|z-?index\s*[:=]\s*['"]?(9{3,}|2147483647|99999|999999)|inset\s*[:=]\s*['"]?0|width\s*[:=]\s*['"]?100(vw|%)|height\s*[:=]\s*['"]?100(vh|%)/i;
const INVISIBLE_STYLE_RE =
  /display\s*[:=]\s*['"]?none|visibility\s*[:=]\s*['"]?hidden|opacity\s*[:=]\s*['"]?0|pointer-events\s*[:=]\s*['"]?none/i;
const FORM_LINK_BUTTON_RE =
  /createElement\(\s*['"](?:form|input|button|a|label)['"]|getElementsByTagName\(\s*['"](?:form|input|button|a)['"]|querySelectorAll?\(\s*['"][^'"]*(?:form|input|button|a\b|\.btn|\.button)/i;
const AD_OR_SEARCH_RE =
  /\.ad[s]?[-_ ]|advertisement|adsbygoogle|search[-_ ]?result|sponsor|tracker|recommendation/i;

export const modificacionPaginasStaticRules: UserRiskStaticRule[] = [
  {
    ruleId: 'page_mod.dom_injection',
    label: 'Inyección o modificación de DOM',
    id: 'modificacion_paginas',
    matches: (finding) => finding.discoveryType === 'inyeccion_dom',
    evidence: (finding) =>
      `Modificación/inyección de DOM o script en ${finding.filePath}:${finding.line}.`,
  },
  {
    ruleId: 'page_mod.remote_script_mv3',
    label: 'Carga de script remoto',
    id: 'modificacion_paginas',
    matches: (finding) => finding.discoveryType === 'script_remoto_mv3',
    evidence: (finding) =>
      `Carga de código remoto en ${finding.filePath}:${finding.line}.`,
  },
  {
    ruleId: 'page_mod.correlation_dom_script',
    label: 'Correlación de modificación de página',
    id: 'modificacion_paginas',
    matches: (finding) =>
      finding.discoveryType === 'correlacion_riesgo' &&
      /dom|script|injection|remote/i.test(finding.detail),
    evidence: (finding) =>
      `Combinación relacionada con modificación de páginas en ${finding.filePath}:${finding.line}.`,
  },
  {
    ruleId: 'page_mod.programmatic_script_execution',
    label: 'Ejecución programática en páginas',
    id: 'modificacion_paginas',
    matches: (finding) =>
      /chrome\.scripting\.executeScript|chrome\.tabs\.executeScript|insertCSS|removeCSS/i.test(
        finding.detail,
      ),
    evidence: (finding) =>
      `Puede inyectar scripts o estilos en páginas desde ${finding.filePath}:${finding.line}.`,
  },
  {
    ruleId: 'page_mod.html_or_frame_injection',
    label: 'Inserción de HTML, scripts o iframes',
    id: 'modificacion_paginas',
    matches: (finding) =>
      /innerHTML|outerHTML|insertAdjacentHTML|appendChild|prepend|createElement\((script|iframe)|\.src remote/i.test(
        finding.detail,
      ),
    evidence: (finding) =>
      `Señal de inserción/modificación visual en ${finding.filePath}:${finding.line}.`,
  },
  {
    ruleId: 'page_mod.form_or_link_replacement',
    label: 'Reemplazo de botones, formularios o enlaces',
    id: 'modificacion_paginas',
    matches: (finding) => FORM_LINK_BUTTON_RE.test(finding.detail),
    evidence: (finding) =>
      `Crea o manipula botones/formularios/enlaces en ${finding.filePath}:${finding.line}.`,
  },
  {
    ruleId: 'page_mod.ad_or_search_replacement',
    label: 'Posible reemplazo de anuncios o resultados',
    id: 'modificacion_paginas',
    matches: (finding) => AD_OR_SEARCH_RE.test(finding.detail),
    evidence: (finding) =>
      `Referencias a anuncios/resultados que podrían sustituirse en ${finding.filePath}:${finding.line}.`,
  },
  {
    ruleId: 'page_mod.invisible_element',
    label: 'Elementos invisibles inyectados',
    id: 'modificacion_paginas',
    matches: (finding) => INVISIBLE_STYLE_RE.test(finding.detail),
    evidence: (finding) =>
      `Manipulación de estilos para ocultar elementos en ${finding.filePath}:${finding.line}.`,
  },
  {
    ruleId: 'page_mod.fake_overlay',
    label: 'Superposición tipo phishing/UI falsa',
    id: 'modificacion_paginas',
    matches: (finding) =>
      OVERLAY_RE.test(finding.detail) ||
      /createElement\(\s*['"](?:div|iframe)['"][\s\S]{0,200}(?:position|z-?index)|modal|overlay|popup|backdrop/i.test(
        finding.detail,
      ),
    evidence: (finding) =>
      `Posible overlay/UI superpuesta (position fixed/absolute o z-index alto) en ${finding.filePath}:${finding.line}.`,
  },
  {
    ruleId: 'page_mod.mutation_observer',
    label: 'Vigilancia silenciosa del DOM',
    id: 'modificacion_paginas',
    matches: (finding) =>
      /MutationObserver|IntersectionObserver|ResizeObserver|attachShadow|shadowRoot/i.test(
        finding.detail,
      ),
    evidence: (finding) =>
      `Observadores del DOM o uso de shadowRoot en ${finding.filePath}:${finding.line}.`,
  },
  {
    ruleId: 'page_mod.history_pushstate',
    label: 'Reescritura de URL en barra de navegación',
    id: 'modificacion_paginas',
    matches: (finding) =>
      /history\.pushState|history\.replaceState/i.test(finding.detail),
    evidence: (finding) =>
      `Reescribe la URL visible al usuario en ${finding.filePath}:${finding.line}.`,
  },
  {
    ruleId: 'page_mod.redirect_or_rewrite',
    label: 'Redirección o reemplazo de contenido',
    id: 'modificacion_paginas',
    matches: (finding) =>
      /redirect|modifyHeaders|declarativeNetRequest|webRequestBlocking|replace|overlay/i.test(
        finding.detail,
      ),
    evidence: (finding) =>
      `Puede alterar navegación, recursos o contenido en ${finding.filePath}:${finding.line}.`,
  },
];

export const evaluateModificacionPaginas: UserRiskCategoryEvaluator = (
  context,
) => {
  const { perms } = context;
  const domInjection = hasFinding(context, 'inyeccion_dom');
  const remoteScript = hasFinding(context, 'script_remoto_mv3');
  const overlaySignal = hasDetail(context, OVERLAY_RE);
  const invisibleSignal = hasDetail(context, INVISIBLE_STYLE_RE);
  const observerSignal = hasDetail(
    context,
    /MutationObserver|IntersectionObserver|attachShadow|shadowRoot/i,
  );
  const formReplacement = hasDetail(context, FORM_LINK_BUTTON_RE);
  // Uso REAL de scripting.executeScript (no solo declarado).
  const usesScriptingExecute = hasApiCall(context, SCRIPTING_EXECUTE_RE);
  const scriptingCall = findApiCall(context, SCRIPTING_EXECUTE_RE);

  // Crítico: code remoto, overlay+inyección DOM (phishing), o inyección
  // de scripts vía chrome.scripting.executeScript con broadHost.
  const isCritical =
    remoteScript ||
    (overlaySignal && domInjection) ||
    (usesScriptingExecute && context.broadHost);
  // Sospechoso: SEÑALES REALES de modificación (no solo permiso declarado).
  // El permiso `scripting` por sí solo, sin uso, queda como capacidad.
  const isSuspicious =
    domInjection ||
    usesScriptingExecute ||
    overlaySignal ||
    invisibleSignal ||
    observerSignal ||
    formReplacement;
  // Capacidad: solo declaración sin uso observado.
  const hasOnlyDeclaration = perms.has('scripting') && !usesScriptingExecute;

  return makeItem(
    context,
    'modificacion_paginas',
    'Modificación de páginas',
    isCritical
      ? 'critico'
      : isSuspicious
        ? 'sospechoso'
        : hasOnlyDeclaration
          ? 'capacidad'
          : 'no_detectado',
    isCritical
      ? usesScriptingExecute && context.broadHost
        ? 'La extensión inserta su propio código dentro de TODAS las páginas que visitas, lo que le permite cambiar su contenido, botones y formularios sin pedirte permiso.'
        : 'La extensión combina capacidades peligrosas de modificación de páginas: puede sobreponer interfaces falsas o alterar formularios — patrón típico de phishing.'
      : isSuspicious
        ? 'La extensión puede modificar el aspecto o contenido de las páginas web que visitas.'
        : hasOnlyDeclaration
          ? 'La extensión tiene permiso para modificar páginas, pero no vimos que lo use activamente.'
          : 'No vimos señales de que esta extensión modifique páginas web.',
    [
      domInjection && 'Detectamos que modifica el contenido de páginas web.',
      usesScriptingExecute &&
        scriptingCall &&
        `Inserta código en páginas usando ${scriptingCall.api} (${scriptingCall.filePath}:${scriptingCall.line}).`,
      perms.has('scripting') &&
        !usesScriptingExecute &&
        'Tiene permiso para insertar código en páginas, pero no vimos que lo use.',
      remoteScript && 'Descarga y ejecuta código desde Internet dentro de las páginas que visitas.',
      overlaySignal &&
        'Puede mostrar ventanas o capas superpuestas sobre la página real — una técnica usada para crear formularios falsos.',
      invisibleSignal &&
        'Puede ocultar elementos de la página haciéndolos invisibles.',
      observerSignal &&
        'Vigila silenciosamente los cambios que ocurren en la página mientras navegas.',
      formReplacement && 'Puede crear, modificar o reemplazar botones, formularios o enlaces.',
      hasDetail(context, /history\.(push|replace)State/i) &&
        'Puede cambiar la dirección web visible en tu barra de navegación sin que realmente cargues otra página.',
    ],
    [
      '¿Puede modificar el contenido de una página web?',
      '¿Puede insertar elementos invisibles dentro de sitios?',
      '¿Puede cambiar botones, formularios o enlaces?',
      '¿Puede reemplazar anuncios o resultados de búsqueda?',
      '¿Puede alterar lo que veo en redes sociales o bancos?',
      '¿Puede superponer interfaces falsas sobre páginas reales?',
    ],
    modificacionPaginasStaticRules,
  );
};
