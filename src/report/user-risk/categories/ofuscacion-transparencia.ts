import {
  hasDetail,
  hasFinding,
  makeItem,
  type UserRiskStaticRule,
  type UserRiskCategoryEvaluator,
} from '../types.js';

const ENCODER_RE =
  /atob\s*\(|String\.fromCharCode\(|String\.fromCodePoint\(|btoa\s*\(|unescape\s*\(|decodeURI(?:Component)?\s*\(/i;
const DYNAMIC_EXEC_RE =
  /\beval\s*\(|new Function\s*\(|setTimeout\(\s*['"]|setInterval\(\s*['"]|Function\(['"]/i;
const HEX_IDENT_RE =
  /_0x[a-fA-F0-9]{2,}|var\s+_0x|let\s+_0x|const\s+_0x|0x[a-fA-F0-9]{4,}\s*[,)\]]/;
const ANTI_DEBUG_RE =
  /debugger\b|devtools|anti[-_ ]?debug|Function\.constructor|performance\.now|console\.clear|toString\(\)\.length|window\.outerWidth\s*-\s*window\.innerWidth|console\.profile|console\.profileEnd/i;
const PACKER_RE =
  /eval\(function\(p,a,c,k,e,[dr]\)|jsfuck|JSFuck|aaencode|obfuscator\.io|webpack[Cc]hunk_|p_a_c_k_e_r/i;

export const ofuscacionTransparenciaStaticRules: UserRiskStaticRule[] = [
  {
    ruleId: 'transparency.obfuscated_code',
    label: 'Código ofuscado',
    id: 'ofuscacion_transparencia',
    matches: (finding) => finding.discoveryType === 'codigo_ofuscado',
    evidence: (finding) =>
      `Código ofuscado o difícil de auditar en ${finding.filePath}:${finding.line}.`,
  },
  {
    ruleId: 'transparency.minified_code',
    label: 'Código minificado',
    id: 'ofuscacion_transparencia',
    matches: (finding) => finding.discoveryType === 'archivo_minificado',
    evidence: (finding) =>
      `Archivo minificado en ${finding.filePath}:${finding.line}.`,
  },
  {
    ruleId: 'transparency.remote_code',
    label: 'Código remoto',
    id: 'ofuscacion_transparencia',
    matches: (finding) => finding.discoveryType === 'script_remoto_mv3',
    evidence: (finding) =>
      `Código remoto dificulta auditoría completa en ${finding.filePath}:${finding.line}.`,
  },
  {
    ruleId: 'transparency.dynamic_execution',
    label: 'Ejecución dinámica',
    id: 'ofuscacion_transparencia',
    matches: (finding) =>
      finding.discoveryType === 'funcion_javascript_riesgosa' &&
      DYNAMIC_EXEC_RE.test(finding.detail),
    evidence: (finding) =>
      `Ejecución dinámica de código en ${finding.filePath}:${finding.line}.`,
  },
  {
    ruleId: 'transparency.encoders',
    label: 'Decodificadores comunes',
    id: 'ofuscacion_transparencia',
    matches: (finding) => ENCODER_RE.test(finding.detail),
    evidence: (finding) =>
      `Usa decodificadores comunes en ofuscación (atob/String.fromCharCode/unescape) en ${finding.filePath}:${finding.line}.`,
  },
  {
    ruleId: 'transparency.hex_identifiers',
    label: 'Identificadores _0x hex',
    id: 'ofuscacion_transparencia',
    matches: (finding) => HEX_IDENT_RE.test(finding.detail),
    evidence: (finding) =>
      `Identificadores con prefijo _0x (típicos de obfuscator.io) en ${finding.filePath}:${finding.line}.`,
  },
  {
    ruleId: 'transparency.packer_signature',
    label: 'Firma de packer conocido',
    id: 'ofuscacion_transparencia',
    matches: (finding) => PACKER_RE.test(finding.detail),
    evidence: (finding) =>
      `Coincide con un packer/ofuscador conocido (Dean Edwards, jsfuck, aaencode, obfuscator.io) en ${finding.filePath}:${finding.line}.`,
  },
  {
    ruleId: 'transparency.correlation_hidden_execution',
    label: 'Correlación de ejecución oculta',
    id: 'ofuscacion_transparencia',
    matches: (finding) =>
      finding.discoveryType === 'correlacion_riesgo' &&
      /obfuscation|remote script|eval/i.test(finding.detail),
    evidence: (finding) =>
      `Combinación que reduce transparencia en ${finding.filePath}:${finding.line}.`,
  },
  {
    ruleId: 'transparency.anti_debugging',
    label: 'Anti-debugging o anti-análisis',
    id: 'ofuscacion_transparencia',
    matches: (finding) => ANTI_DEBUG_RE.test(finding.detail),
    evidence: (finding) =>
      `Señal de anti-debugging/anti-análisis en ${finding.filePath}:${finding.line}.`,
  },
];

export const evaluateOfuscacionTransparencia: UserRiskCategoryEvaluator = (
  context,
) => {
  const obfuscation = hasFinding(context, 'codigo_ofuscado');
  const minified = hasFinding(context, 'archivo_minificado');
  const remoteScript = hasFinding(context, 'script_remoto_mv3');
  const dynamicExec = hasDetail(context, DYNAMIC_EXEC_RE);
  const encoders = hasDetail(context, ENCODER_RE);
  const hexIdents = hasDetail(context, HEX_IDENT_RE);
  const packer = hasDetail(context, PACKER_RE);
  const antiDebug = hasDetail(context, ANTI_DEBUG_RE);

  // Critico: anti-debugging + ofuscación, o packer + ejecución dinámica
  const isCritical =
    (antiDebug && (obfuscation || hexIdents || packer)) ||
    (packer && dynamicExec);
  // Sospechoso: ofuscación, identificadores hex, packer, decoders combinados con eval, o script remoto
  const isSuspicious =
    obfuscation ||
    remoteScript ||
    hexIdents ||
    packer ||
    (encoders && dynamicExec) ||
    antiDebug;

  return makeItem(
    context,
    'ofuscacion_transparencia',
    'Ofuscación y transparencia',
    isCritical
      ? 'critico'
      : isSuspicious
        ? 'sospechoso'
        : minified
          ? 'capacidad'
          : 'no_detectado',
    isCritical
      ? 'La extensión combina ofuscación con anti-debugging o packers conocidos: claramente intenta evadir el análisis.'
      : obfuscation || packer
        ? 'Hay código difícil de auditar. Minificar es normal; ocultar cadenas, reconstruir código o esconder llamadas sensibles es una mala señal.'
        : hexIdents || (encoders && dynamicExec)
          ? 'El código presenta patrones típicos de ofuscación (identificadores _0x, decodificadores + eval).'
          : minified
            ? 'Hay archivos minificados. Esto suele ser normal en producción, pero reduce legibilidad.'
            : 'No vimos señales fuertes de ofuscación.',
    [
      obfuscation && 'Ofuscación/agresiva minificación detectada.',
      minified && 'Archivos minificados detectados.',
      remoteScript && 'Script remoto detectado.',
      packer &&
        'Firma de packer u ofuscador conocido (Dean Edwards, jsfuck, aaencode, obfuscator.io).',
      hexIdents &&
        'Identificadores _0x... (patrón típico de obfuscator.io).',
      encoders &&
        'Uso de decodificadores (atob/String.fromCharCode/unescape).',
      dynamicExec &&
        'Ejecuta código construido dinámicamente (eval/new Function/setTimeout-string).',
      antiDebug &&
        'Señales de anti-debugging (uso de debugger, detección de DevTools, console.clear, performance.now).',
    ],
    [
      '¿El código está ofuscado?',
      '¿El comportamiento de la extensión es entendible?',
      '¿Existen partes imposibles de auditar fácilmente?',
      '¿Usa técnicas anti-debugging?',
    ],
  );
};
