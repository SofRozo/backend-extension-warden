import {
  hasApiCall,
  hasDetail,
  makeItem,
  type UserRiskCategoryEvaluator,
  type UserRiskStaticRule,
} from '../types.js';

// chrome.management APIs used for anti-AV scanning or disabling security extensions.
// getSelf() is intentionally excluded — it's a common benign pattern used to detect
// development mode ("installType === 'development'") and toggle debug logging.
const MGMT_READ_RE =
  /chrome\.management\.(getAll|get|getPermissionWarningsById|getPermissionWarningsByManifest)\b/i;
const MGMT_WRITE_RE =
  /chrome\.management\.(setEnabled|uninstall|uninstallSelf|launchApp)\b/i;
const MGMT_PERM_RE = /\bmanagement\b/i;

export const abusoManagementStaticRules: UserRiskStaticRule[] = [
  {
    ruleId: 'management.permission',
    label: 'Permiso management declarado',
    id: 'abuso_management',
    matches: (finding) =>
      finding.discoveryType === 'permiso_chrome_manifest_riesgoso' &&
      MGMT_PERM_RE.test(finding.detail),
    evidence: (finding) =>
      `Permiso "management" declarado en ${finding.filePath}:${finding.line}.`,
  },
  {
    ruleId: 'management.read_extensions',
    label: 'Lectura de extensiones instaladas',
    id: 'abuso_management',
    matches: (finding) => MGMT_READ_RE.test(finding.detail),
    evidence: (finding) =>
      `Consulta la lista de extensiones instaladas en ${finding.filePath}:${finding.line}.`,
  },
  {
    ruleId: 'management.disable_extension',
    label: 'Deshabilita extensiones de terceros',
    id: 'abuso_management',
    matches: (finding) => MGMT_WRITE_RE.test(finding.detail),
    evidence: (finding) =>
      `Puede deshabilitar o desinstalar otras extensiones en ${finding.filePath}:${finding.line}.`,
  },
];

export const evaluateAbusoManagement: UserRiskCategoryEvaluator = (context) => {
  const hasMgmtPerm = context.perms.has('management');
  const readsExtensions = hasDetail(context, MGMT_READ_RE);
  const disablesExtensions = hasDetail(context, MGMT_WRITE_RE);
  const usesApiActively = hasApiCall(context, /chrome\.management\./i);

  // Critico: puede listar Y deshabilitar extensiones (patrón T1562.001 clásico)
  const isCritical = disablesExtensions;
  // Sospechoso: lee la lista de extensiones instaladas (reconocimiento de herramientas de seguridad)
  const isSuspicious = readsExtensions || (hasMgmtPerm && usesApiActively);
  // Capacidad: solo declara el permiso sin uso en código
  const hasOnlyDeclaration = hasMgmtPerm && !usesApiActively;

  return makeItem(
    context,
    'abuso_management',
    'Abuso de APIs de administración',
    isCritical
      ? 'critico'
      : isSuspicious
        ? 'sospechoso'
        : hasOnlyDeclaration
          ? 'capacidad'
          : 'no_detectado',
    isCritical
      ? 'La extensión puede deshabilitar o desinstalar otras extensiones instaladas. Es la técnica T1562.001 (Disable Tools): el malware la usa para apagar silenciosamente bloqueadores de anuncios, antivirus o extensiones de seguridad antes de operar.'
      : readsExtensions
        ? 'La extensión consulta la lista de extensiones instaladas. Puede estar buscando herramientas de seguridad o ad-blockers para evadirlos.'
        : hasOnlyDeclaration
          ? 'Declara el permiso "management" pero no se observó uso activo en el código analizado.'
          : 'No se detectó uso de APIs de administración de extensiones.',
    [
      hasMgmtPerm && 'Permiso "management" declarado en el manifest.',
      readsExtensions &&
        'Usa chrome.management.getAll/get: puede ver qué extensiones tienes instaladas.',
      disablesExtensions &&
        'Usa chrome.management.setEnabled/uninstall: puede deshabilitar o quitar otras extensiones.',
      !hasMgmtPerm &&
        disablesExtensions &&
        'Llama a chrome.management.uninstallSelf (autodestrucción, común en malware para borrar rastros).',
    ],
    [
      '¿Puede ver qué otras extensiones tengo instaladas?',
      '¿Puede desactivar mi bloqueador de anuncios o antivirus?',
      '¿Puede desinstalarse a sí misma para borrar evidencia?',
      '¿Puede deshabilitar extensiones de seguridad antes de operar?',
    ],
  );
};
