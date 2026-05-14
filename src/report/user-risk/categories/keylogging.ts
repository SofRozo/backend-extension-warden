import {
  hasDetail,
  hasFinding,
  makeItem,
  type UserRiskStaticRule,
  type UserRiskCategoryEvaluator,
} from '../types.js';

const KEY_EVENT_RE =
  /addEventListener\(\s*['"](keydown|keyup|keypress|input|beforeinput|paste|copy|cut|compositionstart|compositionupdate|compositionend)['"]|onkeydown|onkeyup|oninput|onpaste|oncopy|oncut|KeyboardEvent|InputEvent|CompositionEvent|ClipboardEvent/i;
const HOTKEY_RE =
  /ctrlKey|altKey|metaKey|shiftKey|event\.key|event\.code|keyCode|which|chrome\.commands/i;
const PASTE_COPY_RE =
  /addEventListener\(\s*['"](paste|copy|cut)['"]|clipboardData|onpaste|oncopy|oncut/i;
const IME_RE =
  /compositionstart|compositionupdate|compositionend|CompositionEvent/i;
const FORM_SUBMIT_RE =
  /addEventListener\(\s*['"]submit['"]|HTMLFormElement\.prototype\.submit|beforeunload/i;

export const keyloggingStaticRules: UserRiskStaticRule[] = [
  {
    ruleId: 'keylog.keyboard_listener',
    label: 'Listener de teclado o input',
    id: 'keylogging',
    matches: (finding) => finding.discoveryType === 'listener_teclado',
    evidence: (finding) =>
      `Listener de teclado o entrada en ${finding.filePath}:${finding.line}.`,
  },
  {
    ruleId: 'keylog.correlation_keylogger',
    label: 'Correlación de keylogger',
    id: 'keylogging',
    matches: (finding) =>
      finding.discoveryType === 'correlacion_riesgo' &&
      /keyboard|keylogger/i.test(finding.detail),
    evidence: (finding) =>
      `Combinación compatible con keylogging en ${finding.filePath}:${finding.line}.`,
  },
  {
    ruleId: 'keylog.input_event_capture',
    label: 'Captura de eventos de entrada',
    id: 'keylogging',
    matches: (finding) => KEY_EVENT_RE.test(finding.detail),
    evidence: (finding) =>
      `Puede escuchar texto, teclas o eventos de entrada en ${finding.filePath}:${finding.line}.`,
  },
  {
    ruleId: 'keylog.hotkey_monitoring',
    label: 'Monitoreo de atajos',
    id: 'keylogging',
    matches: (finding) => HOTKEY_RE.test(finding.detail),
    evidence: (finding) =>
      `Puede detectar teclas, códigos o atajos en ${finding.filePath}:${finding.line}.`,
  },
  {
    ruleId: 'keylog.clipboard_intercept',
    label: 'Captura de portapapeles (paste/copy/cut)',
    id: 'keylogging',
    matches: (finding) => PASTE_COPY_RE.test(finding.detail),
    evidence: (finding) =>
      `Escucha eventos de pegar/copiar/cortar en ${finding.filePath}:${finding.line}.`,
  },
  {
    ruleId: 'keylog.ime_composition',
    label: 'Eventos de composición IME',
    id: 'keylogging',
    matches: (finding) => IME_RE.test(finding.detail),
    evidence: (finding) =>
      `Escucha eventos de composición (IME): puede capturar texto en idiomas con teclado de composición en ${finding.filePath}:${finding.line}.`,
  },
  {
    ruleId: 'keylog.form_submit_capture',
    label: 'Captura previa al envío',
    id: 'keylogging',
    matches: (finding) => FORM_SUBMIT_RE.test(finding.detail),
    evidence: (finding) =>
      `Captura el formulario justo antes del envío (submit/beforeunload) en ${finding.filePath}:${finding.line}.`,
  },
];

export const evaluateKeylogging: UserRiskCategoryEvaluator = (context) => {
  const keylogger = hasFinding(context, 'listener_teclado');
  const networkFlow = hasFinding(context, 'flujo_datos_a_red');
  const hotkey = hasDetail(context, HOTKEY_RE);
  const pasteCopy = hasDetail(context, PASTE_COPY_RE);
  const ime = hasDetail(context, IME_RE);
  const submitCapture = hasDetail(context, FORM_SUBMIT_RE);

  const anyCaptureSignal =
    keylogger || pasteCopy || ime || hotkey || submitCapture;

  // Critico cuando captura + sale a red
  const isCritical = anyCaptureSignal && networkFlow;
  // Sospechoso cuando hay cualquier señal de captura, aunque no haya sink
  const isSuspicious = anyCaptureSignal;

  return makeItem(
    context,
    'keylogging',
    'Keylogging y captura de teclado',
    isCritical ? 'critico' : isSuspicious ? 'sospechoso' : 'no_detectado',
    isCritical
      ? 'Detectamos captura de teclas o texto combinada con envío a red: patrón típico de keylogger.'
      : keylogger
        ? 'Detectamos listeners de teclado o entrada. Es grave si se combina con envío de datos.'
        : isSuspicious
          ? 'La extensión escucha eventos de entrada (paste/copy, atajos o IME). Puede ser legítimo en gestores de texto o atajos, pero requiere justificación.'
          : 'No vimos señales fuertes de registro de teclas.',
    [
      keylogger && 'Listener de teclado/input detectado.',
      hotkey &&
        'Lee event.key/keyCode/ctrlKey: puede detectar combinaciones y atajos.',
      pasteCopy &&
        'Escucha eventos de paste/copy/cut: puede capturar texto pegado o copiado.',
      ime &&
        'Escucha compositionstart/update/end: captura texto en idiomas con IME (chino, japonés, coreano).',
      submitCapture &&
        'Escucha submit o beforeunload: puede leer formularios antes de enviarse.',
      networkFlow && 'También hay flujo de datos hacia una salida.',
    ],
    [
      '¿Puede registrar teclas que escribo?',
      '¿Escucha todos los eventos del teclado?',
      '¿Puede capturar texto antes de enviarlo?',
      '¿Puede detectar combinaciones de teclas o atajos?',
    ],
  );
};
