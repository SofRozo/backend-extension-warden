import {
  findApiCall,
  hasApiCall,
  makeItem,
  type UserRiskCategoryEvaluator,
  type UserRiskStaticRule,
} from '../types.js';

const SENSITIVE_HOST_RE =
  /bank|paypal|stripe|gmail|outlook|mail|drive|dropbox|onedrive|facebook|instagram|whatsapp|metamask|binance|coinbase|chase|wellsfargo|santander|bbva/i;

const TAB_OBSERVE_RE =
  /^chrome\.tabs\.(query|get|onActivated|onUpdated|onCreated|onRemoved)/;
const NAV_OBSERVE_RE = /^chrome\.webNavigation\./;
const SCRIPTING_EXECUTE_RE =
  /^chrome\.(scripting\.executeScript|tabs\.executeScript|scripting\.insertCSS|tabs\.insertCSS)/;
const TAB_OPEN_RE =
  /^chrome\.tabs\.(create|update|highlight|move)|^window\.open|^location\.(assign|replace)/;

export const accesoGeneralNavegadorStaticRules: UserRiskStaticRule[] = [
  {
    ruleId: 'general.broad_host_or_execution_permission',
    label: 'Permisos amplios de host o ejecución',
    id: 'acceso_general_navegador',
    matches: (finding) =>
      finding.discoveryType === 'permiso_chrome_manifest_riesgoso' &&
      /<all_urls>|\*:\/\/\*\/\*|http:\/\/\*\/\*|https:\/\/\*\/\*|scripting|tabs|activeTab/i.test(
        finding.detail,
      ),
    evidence: (finding) =>
      `Permiso amplio o ejecución sobre sitios detectado en ${finding.filePath}:${finding.line}.`,
  },
  {
    ruleId: 'general.programmatic_script_execution',
    label: 'Ejecución programática de scripts',
    id: 'acceso_general_navegador',
    matches: (finding) =>
      /chrome\.scripting\.executeScript|chrome\.tabs\.executeScript/i.test(
        finding.detail,
      ),
    evidence: (finding) =>
      `Puede ejecutar scripts desde código en ${finding.filePath}:${finding.line}.`,
  },
  {
    ruleId: 'general.tabs_or_navigation_api',
    label: 'Lectura de pestañas o navegación',
    id: 'acceso_general_navegador',
    matches: (finding) =>
      /chrome\.tabs\.query|chrome\.tabs\.get|chrome\.webNavigation|chrome\.windows/i.test(
        finding.detail,
      ),
    evidence: (finding) =>
      `Usa APIs para observar pestañas o navegación en ${finding.filePath}:${finding.line}.`,
  },
  {
    ruleId: 'general.tab_creation_or_open',
    label: 'Apertura programática de pestañas',
    id: 'acceso_general_navegador',
    matches: (finding) =>
      /chrome\.tabs\.create|chrome\.tabs\.update|window\.open|location\.assign|location\.replace/i.test(
        finding.detail,
      ),
    evidence: (finding) =>
      `Puede abrir o redirigir pestañas/ventanas en ${finding.filePath}:${finding.line}.`,
  },
];

export const evaluateAccesoGeneralNavegador: UserRiskCategoryEvaluator = (
  context,
) => {
  const { broadHost, hasContentScript, perms, preprocessed } = context;

  // Auto-execución: content scripts con run_at=document_start o document_end
  // ejecutan sin que el usuario haga clic en el ícono.
  const contentScripts = preprocessed.manifest.contentScripts ?? [];
  const autoRunScripts = contentScripts.some((cs) => {
    const meta = cs as { run_at?: string };
    return meta.run_at === 'document_start' || meta.run_at === 'document_end';
  });

  const hasBackground =
    !!preprocessed.manifest.serviceWorker ||
    (preprocessed.manifest.backgroundScripts?.length ?? 0) > 0;

  // Uso real (no solo declarado) — diferencia capacidad vs sospechoso
  const usesScriptingExecute = hasApiCall(context, SCRIPTING_EXECUTE_RE);
  const usesTabObservation =
    hasApiCall(context, TAB_OBSERVE_RE) || hasApiCall(context, NAV_OBSERVE_RE);
  const usesTabOpen = hasApiCall(context, TAB_OPEN_RE);
  const scriptingCall = findApiCall(context, SCRIPTING_EXECUTE_RE);

  // Sitios sensibles
  const contentMatches = contentScripts.flatMap((cs) => cs.matches);
  const matchesSensitive = contentMatches.some(
    (m) => m === '<all_urls>' || m === '*://*/*' || SENSITIVE_HOST_RE.test(m),
  );
  const hostPermsSensitive = (preprocessed.manifest.hostPermissions ?? []).some(
    (h) => SENSITIVE_HOST_RE.test(h),
  );
  const sensitiveReach = matchesSensitive || hostPermsSensitive;

  const noUiSurface =
    !preprocessed.manifest.popupUrl &&
    !preprocessed.manifest.optionsPage &&
    !preprocessed.manifest.sidePanelPath;
  const invisibleBackgroundExecution =
    (hasBackground || hasContentScript) && noUiSurface;

  // Critico: <all_urls> + scripting.executeScript REAL en background → inyecta
  // código en TODA página visitada desde un proceso invisible al usuario.
  const isCritical =
    broadHost &&
    usesScriptingExecute &&
    (scriptingCall?.fileRole === 'background' || invisibleBackgroundExecution);
  // Sospechoso: uso real de tabs/webNavigation/scripting, o auto-run con broadHost
  const isSuspicious =
    usesScriptingExecute ||
    usesTabObservation ||
    (broadHost && (perms.has('scripting') || autoRunScripts));
  // Capacidad: solo el permiso/manifesto declarado, sin uso real
  const hasOnlyDeclaration = broadHost || perms.has('tabs') || hasContentScript;

  const estado = isCritical
    ? 'critico'
    : isSuspicious
      ? 'sospechoso'
      : hasOnlyDeclaration
        ? 'capacidad'
        : 'no_detectado';

  return makeItem(
    context,
    'acceso_general_navegador',
    'Acceso general al navegador',
    estado,
    isCritical
      ? 'La extensión inserta su código dentro de todas las páginas que visitas y puede actuar sobre ellas en cualquier momento, sin que tú hagas nada.'
      : isSuspicious
        ? 'La extensión accede activamente a información de tus pestañas y páginas — no solo lo declara, sino que lo usa en su código.'
        : hasOnlyDeclaration
          ? 'La extensión tiene permiso para acceder a todas las páginas web, pero no vimos que lo use activamente.'
          : sensitiveReach
            ? 'La extensión declara acceso a sitios sensibles como bancos, correos o redes sociales.'
            : 'No vimos que esta extensión tenga acceso amplio a todos los sitios.',
    [
      broadHost &&
        'Tiene permiso para operar en todos los sitios web que visitas.',
      usesScriptingExecute &&
        scriptingCall &&
        `Inserta código en páginas activamente (${scriptingCall.filePath}:${scriptingCall.line}).`,
      perms.has('scripting') &&
        !usesScriptingExecute &&
        'Tiene permiso para insertar código en páginas, pero no vimos que lo use.',
      usesTabObservation &&
        'Monitorea activamente las pestañas que abres y los sitios que visitas.',
      perms.has('tabs') &&
        !usesTabObservation &&
        'Tiene permiso para ver tus pestañas, pero no vimos que lo use.',
      hasContentScript &&
        'Se ejecuta automáticamente en las páginas que visitas.',
      autoRunScripts &&
        'Comienza a ejecutarse en cuanto cargas una página, antes de que termines de leerla.',
      hasBackground &&
        usesScriptingExecute &&
        'Su proceso de fondo inserta código en páginas activamente — puede hacerlo en respuesta a órdenes remotas.',
      sensitiveReach &&
        'Está configurada para actuar en sitios sensibles: bancos, correo, redes sociales o billeteras digitales.',
      invisibleBackgroundExecution &&
        'No tiene una ventana visible: opera en segundo plano sin que puedas "apagarla" directamente.',
      usesTabOpen &&
        'Puede abrir nuevas pestañas o redirigirte a otras páginas desde código.',
    ],
    [
      '¿Puede ver todas las páginas que visito?',
      '¿Puede actuar en bancos o correos?',
      '¿Realmente necesita acceso a todos los sitios web?',
      '¿Puede ejecutarse automáticamente sin que yo haga clic?',
    ],
    accesoGeneralNavegadorStaticRules,
  );
};
