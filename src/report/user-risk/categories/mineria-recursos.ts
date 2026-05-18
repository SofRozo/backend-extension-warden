import {
  hasDetail,
  hasFinding,
  makeItem,
  type UserRiskCategoryEvaluator,
  type UserRiskStaticRule,
} from '../types.js';

// WebAssembly initialization — the primary vehicle for hidden miners
const WASM_RE =
  /WebAssembly\.(instantiate|compile|compileStreaming|instantiateStreaming)\b|new\s+WebAssembly\.Instance\b/i;

// Web Workers for multi-threaded CPU abuse (miners always use workers)
const WORKER_RE =
  /new\s+Worker\s*\(|new\s+SharedWorker\s*\(/i;

// Known cryptomining pool domains or library signatures (current and legacy)
const MINING_DOMAIN_RE =
  /coinhive|coin-hive|crypto-loot|minero\.pw|webmine\.pro|wshost\.live|hashvault|supportxmr|xmrpool|nanopool|mineXMR|moneroocean|2miners|cryptonight|cnhashing|wasm-miner|monerominer|xmrig\b/i;

// WASM file extensions (common miner delivery)
const WASM_FILE_RE = /\.wasm(?:['"\s?#&)]|$)|application\/wasm/i;

// CPU-throttling / stealth patterns miners use to avoid detection
const STEALTH_MINE_RE =
  /cpuLimit|setThrottle|idle.*mine|mine.*idle|backgroundMine|miner\.start|miner\.stop|hashRate|getHashesPerSecond/i;

// Stratum protocol signatures — miners communicate job/share payloads over
// WebSocket using the Stratum protocol. These strings only appear in mining code.
const STRATUM_RE =
  /"method"\s*:\s*"(mining\.submit|mining\.subscribe|mining\.authorize|login|submit|keepalived)"|stratum\+tcp|stratum\+ssl|"result"\s*:\s*null.*"id"\s*:|pool\.(nonce|difficulty|job_id)|"blob"\s*:|"target"\s*:|"job_id"\s*:/i;

// MV3 service-worker keepalive abuse — miners in MV3 extensions must prevent
// Chrome from suspending the service worker (which happens after ~30s). They do
// this by creating alarms at very short intervals (< 30s) combined with empty
// fetch/WebSocket pings to keep the event loop alive.
const SW_KEEPALIVE_RE =
  /chrome\.alarms\.create.*period|periodInMinutes\s*:\s*0\.|keepAlive|keep_alive|ping.*worker|worker.*ping|self\.registration\.active|clients\.claim\(\)/i;

export const mineriaRecursosStaticRules: UserRiskStaticRule[] = [
  {
    ruleId: 'mining.wasm_init',
    label: 'Inicialización de WebAssembly',
    id: 'mineria_recursos',
    matches: (finding) => WASM_RE.test(finding.detail),
    evidence: (finding) =>
      `Inicializa módulos WebAssembly en ${finding.filePath}:${finding.line}. Puede ejecutar código binario optimizado para minería.`,
  },
  {
    ruleId: 'mining.web_worker',
    label: 'Web Worker (ejecución en segundo plano)',
    id: 'mineria_recursos',
    matches: (finding) => WORKER_RE.test(finding.detail),
    evidence: (finding) =>
      `Crea un Worker para ejecutar código en paralelo en ${finding.filePath}:${finding.line}.`,
  },
  {
    ruleId: 'mining.known_domain',
    label: 'Dominio de minería conocido',
    id: 'mineria_recursos',
    matches: (finding) => MINING_DOMAIN_RE.test(finding.detail),
    evidence: (finding) =>
      `Referencia a un dominio o biblioteca de minería conocida en ${finding.filePath}:${finding.line}.`,
  },
  {
    ruleId: 'mining.wasm_file',
    label: 'Carga de archivo .wasm',
    id: 'mineria_recursos',
    matches: (finding) => WASM_FILE_RE.test(finding.detail),
    evidence: (finding) =>
      `Carga un módulo binario WebAssembly (.wasm) en ${finding.filePath}:${finding.line}.`,
  },
  {
    ruleId: 'mining.stealth_pattern',
    label: 'Patrón de minería encubierta',
    id: 'mineria_recursos',
    matches: (finding) => STEALTH_MINE_RE.test(finding.detail),
    evidence: (finding) =>
      `Referencia a control de CPU, hash rate o patrones de minería en segundo plano en ${finding.filePath}:${finding.line}.`,
  },
  {
    ruleId: 'mining.stratum_protocol',
    label: 'Protocolo Stratum de minería',
    id: 'mineria_recursos',
    matches: (finding) => STRATUM_RE.test(finding.detail),
    evidence: (finding) =>
      `Contiene firmas del protocolo Stratum (mining.submit, mining.subscribe, job_id, etc.) en ${finding.filePath}:${finding.line}.`,
  },
  {
    ruleId: 'mining.sw_keepalive',
    label: 'Keepalive artificial de service worker',
    id: 'mineria_recursos',
    matches: (finding) => SW_KEEPALIVE_RE.test(finding.detail),
    evidence: (finding) =>
      `Intenta mantener el service worker activo artificialmente (patrón MV3 de minería encubierta) en ${finding.filePath}:${finding.line}.`,
  },
];

export const evaluateMineriaRecursos: UserRiskCategoryEvaluator = (context) => {
  const usesWasm = hasDetail(context, WASM_RE) || hasDetail(context, WASM_FILE_RE);
  const usesWorker = hasDetail(context, WORKER_RE);
  const miningDomain = hasDetail(context, MINING_DOMAIN_RE);
  const stealthPattern = hasDetail(context, STEALTH_MINE_RE);
  const stratumSignal = hasDetail(context, STRATUM_RE);
  const swKeepalive = hasDetail(context, SW_KEEPALIVE_RE);
  const networkFlow = hasFinding(context, 'flujo_datos_a_red');

  // Critico solo cuando hay evidencia sólida de minería real:
  //   - Dominio o firma conocida de pool (certeza alta)
  //   - Protocolo Stratum detectado (certeza muy alta)
  //   - Patrón de evasión/stealth (cpuLimit, hashRate, miner.start...)
  //   - Keepalive artificial de SW + WASM (MV3 miner clásico)
  //   - El tridente: WASM + Worker + red (Stratum corre sobre WebSocket)
  //     → sin flujo de red es solo "alto rendimiento legítimo"
  const isCritical =
    miningDomain ||
    stratumSignal ||
    stealthPattern ||
    (swKeepalive && usesWasm) ||
    (usesWasm && usesWorker && networkFlow);

  // Sospechoso: WASM + Worker sin red (legítimo pero merece revisión),
  // o keepalive de SW sin WASM (señal de persistencia anómala)
  const isSuspicious =
    (usesWasm && usesWorker) ||
    (swKeepalive && networkFlow) ||
    usesWasm ||
    usesWorker;

  return makeItem(
    context,
    'mineria_recursos',
    'Minería de recursos / Cryptojacking',
    isCritical ? 'critico' : isSuspicious ? 'sospechoso' : 'no_detectado',
    isCritical
      ? miningDomain
        ? 'La extensión referencia un dominio o librería de minería conocida. Podría estar usando tu CPU para minar sin consentimiento (T1496 - Resource Hijacking).'
        : stratumSignal
          ? 'Contiene firmas del protocolo Stratum (el protocolo que los mineros usan para recibir trabajo y enviar resultados a los pools). Esto prácticamente confirma actividad de minería.'
          : stealthPattern
            ? 'Contiene lógica de control de CPU (hash rate, límites de carga, activación en inactividad). Es la técnica que usan los miners para pasar desapercibidos.'
            : swKeepalive && usesWasm
              ? 'Combina WebAssembly con una técnica para mantener el service worker activo artificialmente. Es el patrón exacto de los cryptominers modernos en extensiones MV3.'
              : 'Combina WebAssembly, Web Workers y envío de datos a la red — el tridente completo del cryptojacking en navegadores.'
      : usesWasm && usesWorker
        ? 'Combina WebAssembly con Web Workers. Esto es legítimo en editores, bases de datos locales o criptografía, pero requiere revisión si no encaja con el propósito declarado.'
        : usesWasm
          ? 'Carga módulos WebAssembly. Legítimo en aplicaciones de alto rendimiento, pero es el vehículo principal de miners ocultos.'
          : usesWorker
            ? 'Usa Web Workers para ejecución paralela. Componente común en miners, pero por sí solo no es conclusivo.'
            : 'No se detectaron señales de minería de recursos.',
    [
      usesWasm && 'Inicializa o carga módulos WebAssembly (.wasm).',
      usesWorker && 'Crea Web Workers para ejecución paralela en segundo plano.',
      networkFlow && usesWasm && 'Combina WASM con envío de datos a la red.',
      miningDomain && 'Referencia a dominio o librería de pool de minería conocido.',
      stratumSignal &&
        'Firmas del protocolo Stratum detectadas (mining.submit, mining.subscribe, job_id, blob, target).',
      stealthPattern &&
        'Lógica de control de CPU, hash rate o activación en modo inactividad.',
      swKeepalive &&
        'Mantiene el service worker activo artificialmente (patrón MV3 de minería encubierta).',
    ],
    [
      '¿Puede usar mi CPU para minar criptomonedas?',
      '¿Puede ralentizar mi computador con cómputo oculto?',
      '¿Carga código binario externo que no puedo inspeccionar?',
      '¿Opera en segundo plano cuando no la estoy usando?',
    ],
    mineriaRecursosStaticRules,
  );
};
