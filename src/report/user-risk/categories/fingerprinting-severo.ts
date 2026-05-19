import {
  hasDetail,
  hasFinding,
  makeItem,
  type UserRiskCategoryEvaluator,
  type UserRiskStaticRule,
} from '../types.js';

// Canvas fingerprinting — renders hidden pixels, reads them back to hash the GPU/font stack
const CANVAS_FP_RE =
  /(?:HTMLCanvasElement\.prototype\.|canvas\.)toDataURL\b|getImageData\b|HTMLCanvasElement\.prototype\.getContext\b/i;

// WebGL advanced fingerprinting — reads GPU model, vendor, driver capabilities
const WEBGL_FP_RE =
  /gl\.getParameter\b|gl\.getExtension\b|WEBGL_debug_renderer_info|WebGLRenderingContext|WebGL2RenderingContext|getContext\(['"](webgl|experimental-webgl|webgl2)/i;

// AudioContext fingerprinting — unique floating-point arithmetic per CPU/OS
const AUDIO_FP_RE =
  /new\s+(?:AudioContext|OfflineAudioContext)\b|createOscillator\b|createAnalyser\b|createDynamicsCompressor\b|getChannelData\b|copyFromChannel\b/i;

// Hardware / OS enumeration signals
const HW_ENUM_RE =
  /navigator\.hardwareConcurrency\b|navigator\.deviceMemory\b|navigator\.platform\b|navigator\.userAgent\b|navigator\.plugins\b|navigator\.mimeTypes\b|navigator\.languages\b|screen\.colorDepth\b|screen\.pixelDepth\b|screen\.width\b|screen\.height\b|window\.devicePixelRatio\b|Intl\.DateTimeFormat\(\)\.resolvedOptions|MediaDevices\.enumerateDevices/i;

// Font enumeration — measures which fonts render at which size to uniquely identify the OS/user
const FONT_ENUM_RE =
  /measureText\b|offsetWidth.*font|fontFamily.*loop|document\.fonts\.check|FontFaceObserver|fontList|installedFonts/i;

// Exfiltration of fingerprint data — confirms the data leaves the device
const FP_EXFIL_RE =
  /fingerprint|fp_hash|browser_id|client_hash|device_hash|visitorId|visitor_id|fp2\b|fingerprintjs|FingerprintJS|@fingerprintjs\/fingerprintjs/i;

export const fingerprintingSeveroStaticRules: UserRiskStaticRule[] = [
  {
    ruleId: 'fp.canvas',
    label: 'Canvas fingerprinting',
    id: 'fingerprinting_severo',
    matches: (finding) => CANVAS_FP_RE.test(finding.detail),
    evidence: (finding) =>
      `Lee píxeles de un canvas oculto para generar huella digital de GPU/fuentes en ${finding.filePath}:${finding.line}.`,
  },
  {
    ruleId: 'fp.webgl',
    label: 'WebGL fingerprinting',
    id: 'fingerprinting_severo',
    matches: (finding) => WEBGL_FP_RE.test(finding.detail),
    evidence: (finding) =>
      `Consulta parámetros WebGL que revelan el modelo de GPU y driver en ${finding.filePath}:${finding.line}.`,
  },
  {
    ruleId: 'fp.audio',
    label: 'AudioContext fingerprinting',
    id: 'fingerprinting_severo',
    matches: (finding) => AUDIO_FP_RE.test(finding.detail),
    evidence: (finding) =>
      `Usa AudioContext/OfflineAudioContext para generar una huella única basada en el hardware de audio en ${finding.filePath}:${finding.line}.`,
  },
  {
    ruleId: 'fp.hardware_enum',
    label: 'Enumeración de hardware/SO',
    id: 'fingerprinting_severo',
    matches: (finding) => HW_ENUM_RE.test(finding.detail),
    evidence: (finding) =>
      `Lee propiedades de hardware o sistema (navigator.hardwareConcurrency, deviceMemory, plugins, screen, etc.) en ${finding.filePath}:${finding.line}.`,
  },
  {
    ruleId: 'fp.font_enum',
    label: 'Enumeración de fuentes del sistema',
    id: 'fingerprinting_severo',
    matches: (finding) => FONT_ENUM_RE.test(finding.detail),
    evidence: (finding) =>
      `Mide o enumera fuentes del sistema para generar una huella única del usuario en ${finding.filePath}:${finding.line}.`,
  },
  {
    ruleId: 'fp.exfiltration_library',
    label: 'Librería o hash de fingerprint',
    id: 'fingerprinting_severo',
    matches: (finding) => FP_EXFIL_RE.test(finding.detail),
    evidence: (finding) =>
      `Referencia a FingerprintJS u otra librería de identificación biométrica en ${finding.filePath}:${finding.line}.`,
  },
];

export const evaluateFingerprintingSevero: UserRiskCategoryEvaluator = (
  context,
) => {
  const canvas = hasDetail(context, CANVAS_FP_RE);
  const webgl = hasDetail(context, WEBGL_FP_RE);
  const audio = hasDetail(context, AUDIO_FP_RE);
  const hwEnum = hasDetail(context, HW_ENUM_RE);
  const fontEnum = hasDetail(context, FONT_ENUM_RE);
  const fpLib = hasDetail(context, FP_EXFIL_RE);
  const networkFlow = hasFinding(context, 'flujo_datos_a_red');

  // Cuenta cuántas técnicas distintas de fingerprint se usan
  const techniqueCount = [canvas, webgl, audio, hwEnum, fontEnum].filter(
    Boolean,
  ).length;

  // Critico: librería de FP conocida, o 2+ técnicas de fingerprint + envío a red,
  // o 3+ técnicas de fingerprint (identificación sistemática T1082)
  const isCritical =
    fpLib || (techniqueCount >= 2 && networkFlow) || techniqueCount >= 3;

  // Sospechoso: al menos una técnica activa de fingerprint, o 2+ técnicas sin red
  const isSuspicious = techniqueCount >= 1 || fontEnum;

  return makeItem(
    context,
    'fingerprinting_severo',
    'Fingerprinting severo',
    isCritical ? 'critico' : isSuspicious ? 'sospechoso' : 'no_detectado',
    isCritical
      ? fpLib
        ? 'La extensión utiliza FingerprintJS u otra librería especializada para crear un identificador único y permanente de tu dispositivo. Esto viola la privacidad bajo marcos como GDPR (T1082 - System Information Discovery).'
        : networkFlow
          ? `Combina ${techniqueCount} técnicas distintas de fingerprinting (canvas, WebGL, audio, hardware, fuentes) con envío de datos a la red. Tu dispositivo puede ser identificado de forma única y permanente entre diferentes sitios web.`
          : `Usa ${techniqueCount} técnicas distintas de fingerprinting simultáneamente. Es el patrón típico de Data Brokers que crean perfiles de usuario sin cookies.`
      : canvas
        ? 'Lee píxeles de canvas ocultos. Es la técnica de fingerprinting más común para identificar GPUs y stacks de fuentes.'
        : webgl
          ? 'Consulta parámetros WebGL que revelan el modelo de GPU y driver del usuario.'
          : audio
            ? 'Usa AudioContext para generar un fingerprint basado en el hardware de audio.'
            : hwEnum
              ? 'Lee propiedades de hardware y SO (CPU cores, memoria, idioma, resolución). Individualmente son datos normales, pero combinados forman una huella única.'
              : 'No se detectaron técnicas de fingerprinting severo.',
    [
      canvas &&
        'Canvas fingerprinting: renderiza texto/formas ocultos y lee los píxeles resultantes.',
      webgl &&
        'WebGL fingerprinting: consulta gl.getParameter() con WEBGL_debug_renderer_info para identificar la GPU.',
      audio &&
        'AudioContext fingerprinting: procesa señales de audio para detectar variaciones únicas del hardware de audio.',
      hwEnum &&
        'Enumera propiedades de hardware/SO: navigator.hardwareConcurrency, deviceMemory, plugins, screen, etc.',
      fontEnum &&
        'Enumeración de fuentes del sistema: mide qué fuentes están instaladas para crear una huella del SO/usuario.',
      fpLib &&
        'Usa FingerprintJS u otra librería especializada para calcular y almacenar un hash persistente del dispositivo.',
      networkFlow &&
        techniqueCount > 0 &&
        'Los datos de fingerprinting son enviados a la red.',
    ],
    [
      '¿Puede identificarme de forma única sin cookies?',
      '¿Puede rastrearme entre diferentes sitios web?',
      '¿Crea un perfil permanente de mi dispositivo?',
      '¿Vende o comparte mi huella digital con terceros?',
      '¿Viola mi privacidad incluso en modo incógnito?',
    ],
    fingerprintingSeveroStaticRules,
  );
};
