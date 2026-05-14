import {
  hasDetail,
  makeItem,
  type UserRiskCategoryEvaluator,
  type UserRiskStaticRule,
} from '../types.js';

const SENSITIVE_HOST_RE =
  /bank|paypal|stripe|gmail|outlook|mail|drive|dropbox|onedrive|facebook|instagram|whatsapp|metamask|binance|coinbase|chase|wellsfargo|santander|bbva/i;

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

  // Background/service worker = ejecución autónoma sin interacción del usuario.
  const hasBackground =
    !!preprocessed.manifest.serviceWorker ||
    (preprocessed.manifest.backgroundScripts?.length ?? 0) > 0;

  // ¿Matchea sitios sensibles? (bancos, mail, redes, billeteras)
  const contentMatches = contentScripts.flatMap((cs) => cs.matches);
  const matchesSensitive = contentMatches.some(
    (m) =>
      m === '<all_urls>' ||
      m === '*://*/*' ||
      SENSITIVE_HOST_RE.test(m),
  );
  const hostPermsSensitive = (preprocessed.manifest.hostPermissions ?? []).some(
    (h) => SENSITIVE_HOST_RE.test(h),
  );

  const sensitiveReach = matchesSensitive || hostPermsSensitive;

  // Extensión sin UI visible (sin popup ni options) que sí inyecta en páginas
  // = corre invisiblemente.
  const noUiSurface =
    !preprocessed.manifest.popupUrl &&
    !preprocessed.manifest.optionsPage &&
    !preprocessed.manifest.sidePanelPath;
  const invisibleBackgroundExecution =
    (hasBackground || hasContentScript) && noUiSurface;

  // Estado: crítico si tiene <all_urls> + scripting o auto-run + invisibilidad,
  // sospechoso si tiene broadHost o ejecución programática, capacidad si solo tabs.
  const estado =
    (broadHost && (perms.has('scripting') || autoRunScripts)) ||
    invisibleBackgroundExecution
      ? 'sospechoso'
      : broadHost || perms.has('tabs') || hasContentScript
        ? 'capacidad'
        : 'no_detectado';

  return makeItem(
    context,
    'acceso_general_navegador',
    'Acceso general al navegador',
    estado,
    broadHost
      ? 'La extensión tiene capacidad para actuar o leer información en muchos o todos los sitios. Esto puede ser legítimo, pero debe estar justificado por su propósito.'
      : sensitiveReach
        ? 'La extensión declara acceso a sitios sensibles (bancos, correos o redes).'
        : 'No vimos permisos amplios para todos los sitios.',
    [
      broadHost && 'Permisos o content scripts sobre <all_urls> / *://*/*.',
      perms.has('scripting') && 'Permiso scripting: puede inyectar código.',
      perms.has('activeTab') &&
        'Permiso activeTab: gana acceso temporal a la pestaña activa.',
      perms.has('tabs') && 'Permiso tabs: puede ver URLs y títulos.',
      hasContentScript && 'Tiene content scripts que se ejecutan en páginas.',
      autoRunScripts &&
        'Content scripts con run_at=document_start/end: arrancan automáticamente al cargar la página.',
      hasBackground &&
        'Tiene background/service worker: corre en segundo plano sin interacción del usuario.',
      sensitiveReach &&
        'Sus matches o host_permissions incluyen sitios sensibles (banca, correo, redes, billeteras).',
      invisibleBackgroundExecution &&
        'Corre sin UI visible (sin popup ni options): el usuario no tiene una forma directa de "encenderla" o "apagarla".',
      hasDetail(context, /chrome\.tabs\.create|chrome\.tabs\.update|window\.open/i) &&
        'Puede abrir/redirigir pestañas desde código.',
    ],
    [
      '¿Puede ver todas las páginas que visito?',
      '¿Puede actuar en bancos o correos?',
      '¿Realmente necesita acceso a todos los sitios web?',
      '¿Puede ejecutarse automáticamente sin que yo haga clic?',
    ],
  );
};
