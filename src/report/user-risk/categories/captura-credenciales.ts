import {
  hasDetail,
  hasFinding,
  makeItem,
  type UserRiskStaticRule,
  type UserRiskCategoryEvaluator,
} from '../types.js';

const CREDENTIAL_RE =
  /credential theft|password|input\[type=["']?password|access_token|refresh_token|privatekey|seed phrase|mnemonic/i;
const PASSWORD_FIELD_RE =
  /input\[type=["']?password|credential selector:password|password field|autocomplete=["']?(?:current|new)-password|name=["']?password|name=["']?passwd|name=["']?pwd/i;
const TOKEN_RE =
  /access_token|refresh_token|id_token|bearer|authorization|x-auth|api[_-]?key|jwt\b|oauth|session[_-]?id|csrftoken/i;
const FORM_INTERCEPT_RE =
  /addEventListener\(\s*['"]submit['"]|HTMLFormElement\.prototype\.submit|preventDefault|FormData|\.elements\[|new FormData/i;
const IDENTITY_API_RE =
  /chrome\.identity\.getAuthToken|chrome\.identity\.launchWebAuthFlow|chrome\.identity\.getProfileUserInfo|chrome\.identity\.getAccounts/i;

export const capturaCredencialesStaticRules: UserRiskStaticRule[] = [
  {
    ruleId: 'creds.cookie_access',
    label: 'Acceso a cookies de sesión',
    id: 'captura_credenciales',
    matches: (finding) => finding.discoveryType === 'lectura_cookies',
    evidence: (finding) =>
      `Lectura/escritura de cookies en ${finding.filePath}:${finding.line}.`,
  },
  {
    ruleId: 'creds.sensitive_flow',
    label: 'Credencial en flujo de datos',
    id: 'captura_credenciales',
    matches: (finding) =>
      finding.discoveryType === 'flujo_datos_a_red' &&
      /cookie|password|credential|token|bearer|privatekey|seed phrase|mnemonic|sessionStorage|localStorage|chrome\.storage/i.test(
        finding.detail,
      ),
    evidence: (finding) =>
      `Dato de sesión o credencial aparece en un flujo (${finding.filePath}:${finding.line}).`,
  },
  {
    ruleId: 'creds.correlation_session_exfil',
    label: 'Correlación de sesión/exfiltración',
    id: 'captura_credenciales',
    matches: (finding) =>
      finding.discoveryType === 'correlacion_riesgo' &&
      /credential|password|cookie|session|token|exfiltration/i.test(
        finding.detail,
      ),
    evidence: (finding) =>
      `Combinación de señales sobre credenciales/sesión en ${finding.filePath}:${finding.line}.`,
  },
  {
    ruleId: 'creds.secret_reference',
    label: 'Referencia a secreto o credencial',
    id: 'captura_credenciales',
    matches: (finding) => CREDENTIAL_RE.test(finding.detail),
    evidence: (finding) =>
      `Referencia a credenciales o secretos en ${finding.filePath}:${finding.line}.`,
  },
  {
    ruleId: 'creds.password_selector',
    label: 'Selector de campo de contraseña',
    id: 'captura_credenciales',
    matches: (finding) => PASSWORD_FIELD_RE.test(finding.detail),
    evidence: (finding) =>
      `Busca campos de contraseña en ${finding.filePath}:${finding.line}.`,
  },
  {
    ruleId: 'creds.token_reference',
    label: 'Token de autenticación',
    id: 'captura_credenciales',
    matches: (finding) => TOKEN_RE.test(finding.detail),
    evidence: (finding) =>
      `Referencia a token/JWT/Bearer en ${finding.filePath}:${finding.line}.`,
  },
  {
    ruleId: 'creds.form_interception',
    label: 'Intercepción de formularios',
    id: 'captura_credenciales',
    matches: (finding) => FORM_INTERCEPT_RE.test(finding.detail),
    evidence: (finding) =>
      `Puede observar o interceptar formularios antes del envío en ${finding.filePath}:${finding.line}.`,
  },
  {
    ruleId: 'creds.auth_storage',
    label: 'Tokens en storage',
    id: 'captura_credenciales',
    matches: (finding) =>
      /localStorage|sessionStorage|chrome\.storage|access_token|refresh_token|authorization|bearer/i.test(
        finding.detail,
      ),
    evidence: (finding) =>
      `Señal de tokens o estado de sesión en almacenamiento en ${finding.filePath}:${finding.line}.`,
  },
  {
    ruleId: 'creds.chrome_identity',
    label: 'API chrome.identity',
    id: 'captura_credenciales',
    matches: (finding) => IDENTITY_API_RE.test(finding.detail),
    evidence: (finding) =>
      `Usa chrome.identity para obtener tokens de cuenta Google/OAuth en ${finding.filePath}:${finding.line}.`,
  },
  {
    ruleId: 'creds.cookies_permission',
    label: 'Permiso cookies declarado',
    id: 'captura_credenciales',
    matches: (finding) =>
      finding.discoveryType === 'permiso_chrome_manifest_riesgoso' &&
      /\bcookies\b/i.test(finding.detail),
    evidence: (finding) =>
      `Permiso "cookies" declarado en manifest — puede acceder a sesiones activas en ${finding.filePath}:${finding.line}.`,
  },
];

export const evaluateCapturaCredenciales: UserRiskCategoryEvaluator = (
  context,
) => {
  const credentialSignal = hasDetail(context, CREDENTIAL_RE);
  const passwordSelector = hasDetail(context, PASSWORD_FIELD_RE);
  const tokenSignal = hasDetail(context, TOKEN_RE);
  const cookieRead = hasFinding(context, 'lectura_cookies');
  const credentialFlow = context.positives.some(
    (finding) =>
      finding.discoveryType === 'flujo_datos_a_red' &&
      /cookie|password|credential|token|bearer|privatekey|seed phrase|mnemonic|sessionStorage|localStorage|chrome\.storage/i.test(
        finding.detail,
      ),
  );
  const storageSignal = hasDetail(
    context,
    /sessionStorage|localStorage|chrome\.storage/i,
  );
  const formIntercept = hasDetail(context, FORM_INTERCEPT_RE);
  const identityApi = hasDetail(context, IDENTITY_API_RE);

  // Critico: cualquier señal de credencial + envío a red, o pwd selector + form intercept
  const isCritical =
    (credentialSignal || passwordSelector || tokenSignal || cookieRead) &&
    credentialFlow;
  const isPwdInterception = passwordSelector && formIntercept;
  // Sospechoso: cualquier señal de credencial individual o cookies/identity
  const isSuspicious =
    credentialSignal ||
    passwordSelector ||
    tokenSignal ||
    cookieRead ||
    formIntercept ||
    identityApi ||
    context.perms.has('cookies');

  return makeItem(
    context,
    'captura_credenciales',
    'Contraseñas, tokens y sesiones',
    isCritical || isPwdInterception
      ? 'critico'
      : isSuspicious
        ? 'sospechoso'
        : storageSignal
          ? 'capacidad'
          : 'no_detectado',
    isCritical
      ? 'La extensión combina acceso a contraseñas o sesiones con envío de datos a servidores — patrón clásico de robo de credenciales.'
      : isPwdInterception
        ? 'La extensión busca campos de contraseña e intercepta el envío de formularios — puede capturar lo que escribes antes de que llegue al sitio.'
        : cookieRead || context.perms.has('cookies')
          ? 'La extensión puede acceder a las cookies de los sitios que visitas, donde se guardan tus sesiones activas.'
          : isSuspicious
            ? 'La extensión hace referencia a contraseñas, tokens o APIs de autenticación en su código.'
            : storageSignal
              ? 'Vimos acceso a almacenamiento donde podrían guardarse tokens o datos de sesión.'
              : 'No vimos señales de que esta extensión capture contraseñas o credenciales.',
    [
      credentialSignal &&
        'El código hace referencia explícita a contraseñas, tokens o frases de recuperación.',
      passwordSelector &&
        'Busca activamente los campos de contraseña en las páginas que visitas.',
      tokenSignal &&
        'El código contiene referencias a tokens de sesión o claves de autenticación.',
      cookieRead &&
        'Puede leer las cookies del sitio — ahí se guardan tus sesiones activas.',
      context.perms.has('cookies') &&
        'Tiene permiso para acceder a las cookies de los sitios.',
      formIntercept &&
        'Puede capturar los datos de un formulario antes de que los envíes.',
      identityApi &&
        'Usa la API de Chrome para obtener tokens de tu cuenta de Google sin que lo veas.',
      credentialFlow &&
        'Datos de sesión o credenciales detectados viajando hacia servidores externos.',
    ],
    [
      '¿Puede capturar contraseñas?',
      '¿Puede leer usuarios y sesiones activas?',
      '¿Puede interceptar formularios antes de ser enviados?',
      '¿Puede capturar tokens de autenticación?',
      '¿Puede acceder a cookies de sesión?',
    ],
    capturaCredencialesStaticRules,
  );
};
