/**
 * test_malicious_extensions.mjs — Script de pruebas de tesis
 *
 * Envía extensiones .crx al backend, espera los resultados y:
 *   - Guarda el JSON completo de cada job en la carpeta del batch correspondiente
 *     con nombre: <jobId>-<nombre_extension>.json
 *   - Genera un Excel por batch dentro de su carpeta
 *
 * Uso:
 *   node test_malicious_extensions.mjs
 *   node test_malicious_extensions.mjs --count 50 --batch 10
 *   node test_malicious_extensions.mjs --count 100 --batch 25 --delay 3
 *   node test_malicious_extensions.mjs --url http://localhost:3000 --count 20 --batch 5
 *
 * Parámetros:
 *   --url    URL del backend          (default: http://localhost:3000)
 *   --dir    Carpeta con los .crx     (default: ../../Malicious Browser Extensions)
 *   --out    Carpeta raíz de salida   (default: ./resultados/<timestamp>)
 *   --count  Total de extensiones     (default: 50)
 *   --batch  Extensiones por batch    (default: 10)
 *   --delay  Segundos entre envíos    (default: 2)
 *
 * Requiere Node 18+.  exceljs ya está en el package.json del backend.
 */

import fs   from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ── Configuración por defecto ────────────────────────────────────────────────
const DEFAULTS = {
  url:   'http://localhost:3000',
  dir:   path.join(__dirname, '..', '..', 'Malicious Browser Extensions'),
  out:   path.join(__dirname, 'resultados', new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19)),
  count: 50,
  batch: 10,
  delay: 2,
};
const POLL_INTERVAL_MS = 10_000;
const MAX_WAIT_MS      = 1_320_000; // 22 min — cubre runs lentos de LLM con qwen3:8b

// ── Argumentos CLI ───────────────────────────────────────────────────────────
function parseArgs() {
  const args = process.argv.slice(2);
  const cfg  = { ...DEFAULTS };
  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case '--url':   cfg.url   = args[++i]; break;
      case '--dir':   cfg.dir   = args[++i]; break;
      case '--out':   cfg.out   = args[++i]; break;
      case '--count': cfg.count = parseInt(args[++i], 10); break;
      case '--batch': cfg.batch = parseInt(args[++i], 10); break;
      case '--delay': cfg.delay = parseFloat(args[++i]); break;
    }
  }
  return cfg;
}

// ── HTTP helpers ─────────────────────────────────────────────────────────────
async function checkHealth(baseUrl) {
  try {
    const r = await fetch(`${baseUrl}/health/ready`, { signal: AbortSignal.timeout(10_000) });
    return r.ok;
  } catch { return false; }
}

async function uploadExtension(baseUrl, filePath) {
  const filename = path.basename(filePath);
  const buffer   = fs.readFileSync(filePath);
  const boundary = `----FormBoundary${Date.now().toString(16)}`;
  const header   = Buffer.from(
    `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="${filename}"\r\n` +
    `Content-Type: application/octet-stream\r\n\r\n`
  );
  const footer = Buffer.from(`\r\n--${boundary}--\r\n`);
  const body   = Buffer.concat([header, buffer, footer]);

  const resp = await fetch(`${baseUrl}/analyze/upload`, {
    method:  'POST',
    headers: { 'Content-Type': `multipart/form-data; boundary=${boundary}` },
    body,
    signal:  AbortSignal.timeout(60_000),
  });
  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`HTTP ${resp.status}: ${text.slice(0, 200)}`);
  }
  return resp.json();
}

async function pollStatus(baseUrl, jobId) {
  const deadline = Date.now() + MAX_WAIT_MS;
  while (Date.now() < deadline) {
    await sleep(POLL_INTERVAL_MS);
    try {
      const r    = await fetch(`${baseUrl}/status/${jobId}`, { signal: AbortSignal.timeout(15_000) });
      const data = await r.json();
      const st   = data.status ?? 'unknown';
      const prog = data.progress ?? 0;
      process.stdout.write(`    → [${String(prog).padStart(3)}%] ${st}       \r`);
      if (st === 'completed' || st === 'failed') {
        process.stdout.write('\n');
        return data;
      }
    } catch (e) {
      process.stdout.write(`\n    ! polling error: ${e.message}\n`);
    }
  }
  process.stdout.write('\n');
  return { status: 'timeout', jobId };
}

async function getReport(baseUrl, jobId) {
  const r = await fetch(`${baseUrl}/report/${jobId}`, { signal: AbortSignal.timeout(30_000) });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

// ── Extraer métricas del reporte ─────────────────────────────────────────────
//
// Estructura actual del reporte (sin análisis dinámico):
//   report.agente1                    — { proposito, explicacion, veredicto_global,
//                                         nivel_riesgo_inicial, categoria,
//                                         respuestas_usuario: { key: {valor, razon} } }
//   report.veredicto_usuario          — { veredicto, nivel, resumen, razones[] }
//   report.resumen_usuario            — [{ id, estado, ... }]
//   report.puntuacion_riesgo          — { score, level, reasons[] }
//   report.permisos_no_usados         — [{ permission, categoria, descripcion }]
//   report.estructura.resultado1      — VerdictedStaticFinding[]
//   report.estructura.resultado2_priority — VerdictedDomainFinding[]  (sensibles)
//   report.estructura.resultado2_unknown  — VerdictedDomainFinding[]  (desconocidos)
//   report.hallazgos_estaticos_positivos  — string[]
//
function buildRow(index, filename, upload, statusResp, report, elapsedS, error = '') {
  if (!report) {
    return {
      '#':                          index,
      archivo:                      filename,
      job_id:                       upload?.jobId ?? '',
      estado_job:                   statusResp?.status ?? 'unknown',
      // Agente 1
      veredicto_agente:             '',
      nivel_riesgo_agente:          '',
      categoria_agente:             '',
      proposito:                    '',
      explicacion:                  '',
      // Veredicto usuario (determinista + agente)
      veredicto_usuario:            '',
      nivel_usuario:                '',
      resumen_usuario:              '',
      razones_usuario:              '',
      // Respuestas FAQ (valor solamente para el resumen tabular)
      faq_puede_capturar_contrasenas:      '',
      faq_puede_registrar_teclas:          '',
      faq_puede_espiar_sin_saberlo:        '',
      faq_puede_leer_formularios:          '',
      faq_puede_modificar_paginas:         '',
      faq_puede_interceptar_trafico:       '',
      faq_puede_ver_paginas_visitadas:     '',
      faq_puede_ver_historial:             '',
      faq_codigo_oculto_o_sospechoso:      '',
      faq_puede_afectar_otras_extensiones: '',
      // Risk score
      risk_score:                   '',
      risk_level:                   '',
      // Hallazgos estáticos
      hallazgos_positivos_total:    '',
      hallazgos_criticos:           '',
      hallazgos_altos:              '',
      hallazgos_medios:             '',
      hallazgos_bajos:              '',
      // 13 categorías de comportamiento
      cat_acceso_general:           '',
      cat_modificacion_paginas:     '',
      cat_lectura_informacion:      '',
      cat_captura_credenciales:     '',
      cat_keylogging:               '',
      cat_seguimiento_privacidad:   '',
      cat_manipulacion_trafico:     '',
      cat_acceso_historial:         '',
      cat_descargas_archivos:       '',
      cat_abuso_management:         '',
      cat_mineria_recursos:         '',
      cat_fingerprinting_severo:    '',
      cat_ofuscacion_transparencia: '',
      // Dominios
      dominios_prioritarios:        '',
      dominios_desconocidos:        '',
      dominios_sensibles_lista:     '',
      // Permisos no usados
      permisos_no_usados_total:     '',
      permisos_no_usados_criticos:  '',
      permisos_no_usados_lista:     '',
      // Tiempos
      duracion_analisis_s:          elapsedS.toFixed(1),
      error,
    };
  }

  const agente1    = report.agente1    ?? {};
  const estructura = report.estructura ?? {};
  const resultado1 = estructura.resultado1          ?? [];
  const prio       = estructura.resultado2_priority ?? [];
  const unknown    = estructura.resultado2_unknown  ?? [];
  const verdUsr    = report.veredicto_usuario        ?? {};
  const riskScore  = report.puntuacion_riesgo        ?? {};
  const resumenUsr = report.resumen_usuario          ?? [];
  const permNoUsd  = report.permisos_no_usados       ?? [];

  // respuestas_usuario ahora viven dentro de agente1 con forma {valor, razon}
  const faq = agente1.respuestas_usuario ?? {};
  const faqVal = key => {
    const entry = faq[key];
    if (!entry) return '';
    // compatibilidad con JSONs viejos (cadena plana) y nueva estructura ({valor, razon})
    return typeof entry === 'object' ? (entry.valor ?? '') : entry;
  };

  // Hallazgos estáticos positivos
  const positivos = resultado1.filter(f => f.veredicto === 'positivo');
  const bySev     = sev => positivos.filter(f => f.severity === sev).length;

  // Estado por categoría (las 13 del resumen_usuario)
  const catStatus = id => {
    const item = resumenUsr.find(c => c.id === id);
    return item ? item.estado : 'no_detectado';
  };

  // Dominios sensibles (resultado2_priority): listar primeros 5 dominios
  const domSensiblesList = prio
    .map(f => f.domain)
    .filter((d, i, arr) => arr.indexOf(d) === i)
    .slice(0, 5)
    .join(', ');

  // Permisos no usados
  const permNoUsdCriticos = permNoUsd.filter(p => p.categoria === 'critical' || p.categoria === 'high').length;
  const permNoUsdLista    = permNoUsd.map(p => p.permission).slice(0, 8).join(', ');

  return {
    '#':                          index,
    archivo:                      filename,
    job_id:                       upload?.jobId ?? '',
    estado_job:                   statusResp?.status ?? 'unknown',
    // Agente 1
    veredicto_agente:             agente1.veredicto_global        ?? '',
    nivel_riesgo_agente:          agente1.nivel_riesgo_inicial    ?? '',
    categoria_agente:             agente1.categoria               ?? '',
    proposito:                    (agente1.proposito              ?? '').slice(0, 200),
    explicacion:                  (agente1.explicacion            ?? '').slice(0, 300),
    // Veredicto usuario (combinación agente + determinista)
    veredicto_usuario:            verdUsr.veredicto  ?? '',
    nivel_usuario:                verdUsr.nivel      ?? '',
    resumen_usuario:              (verdUsr.resumen   ?? '').slice(0, 200),
    razones_usuario:              (verdUsr.razones   ?? []).join(' | ').slice(0, 300),
    // Respuestas FAQ — valor del agente (si / posible / no_detectado)
    faq_puede_capturar_contrasenas:      faqVal('puede_capturar_contrasenas'),
    faq_puede_registrar_teclas:          faqVal('puede_registrar_teclas'),
    faq_puede_espiar_sin_saberlo:        faqVal('puede_espiar_sin_saberlo'),
    faq_puede_leer_formularios:          faqVal('puede_leer_formularios'),
    faq_puede_modificar_paginas:         faqVal('puede_modificar_paginas'),
    faq_puede_interceptar_trafico:       faqVal('puede_interceptar_trafico'),
    faq_puede_ver_paginas_visitadas:     faqVal('puede_ver_paginas_visitadas'),
    faq_puede_ver_historial:             faqVal('puede_ver_historial'),
    faq_codigo_oculto_o_sospechoso:      faqVal('codigo_oculto_o_sospechoso'),
    faq_puede_afectar_otras_extensiones: faqVal('puede_afectar_otras_extensiones'),
    // Risk score
    risk_score:                   riskScore.score ?? '',
    risk_level:                   riskScore.level ?? '',
    // Hallazgos estáticos (solo positivos)
    hallazgos_positivos_total:    positivos.length,
    hallazgos_criticos:           bySev('critical'),
    hallazgos_altos:              bySev('high'),
    hallazgos_medios:             bySev('medium'),
    hallazgos_bajos:              bySev('low'),
    // 13 categorías de comportamiento
    cat_acceso_general:           catStatus('acceso_general_navegador'),
    cat_modificacion_paginas:     catStatus('modificacion_paginas'),
    cat_lectura_informacion:      catStatus('lectura_informacion'),
    cat_captura_credenciales:     catStatus('captura_credenciales'),
    cat_keylogging:               catStatus('keylogging'),
    cat_seguimiento_privacidad:   catStatus('seguimiento_privacidad'),
    cat_manipulacion_trafico:     catStatus('manipulacion_trafico'),
    cat_acceso_historial:         catStatus('acceso_historial'),
    cat_descargas_archivos:       catStatus('descargas_archivos'),
    cat_abuso_management:         catStatus('abuso_management'),
    cat_mineria_recursos:         catStatus('mineria_recursos'),
    cat_fingerprinting_severo:    catStatus('fingerprinting_severo'),
    cat_ofuscacion_transparencia: catStatus('ofuscacion_transparencia'),
    // Dominios
    dominios_prioritarios:        prio.length,
    dominios_desconocidos:        unknown.length,
    dominios_sensibles_lista:     domSensiblesList,
    // Permisos declarados pero no usados
    permisos_no_usados_total:     permNoUsd.length,
    permisos_no_usados_criticos:  permNoUsdCriticos,
    permisos_no_usados_lista:     permNoUsdLista,
    // Tiempo
    duracion_analisis_s:          elapsedS.toFixed(1),
    error,
  };
}

// ── Excel (un archivo por batch) ─────────────────────────────────────────────
async function loadExcelJS() {
  try {
    const mod = await import('../node_modules/exceljs/dist/es5/index.nodejs.js');
    return mod.default ?? mod;
  } catch {
    try {
      return (await import('exceljs')).default;
    } catch {
      return null;
    }
  }
}

async function exportBatchExcel(ExcelJS, rows, outPath, batchLabel) {
  if (!ExcelJS) {
    console.log('  (exceljs no disponible — omitiendo Excel)');
    return;
  }

  const wb = new ExcelJS.Workbook();
  wb.creator = 'ExtWarden-batch-test';
  wb.created = new Date();

  // ── Hoja 1: Resultados detallados ────────────────────────────────────────
  const ws   = wb.addWorksheet('Resultados');
  const keys = Object.keys(rows[0] ?? {});

  const HEADER_COLOR = 'FF1F4E79';
  const STATUS_COLORS = {
    critico:        'FFFF4C4C',
    critical:       'FFFF4C4C',
    maliciosa:      'FFFFC7CE',
    alto:           'FFFF9933',
    high:           'FFFF9933',
    sospechosa:     'FFFFEB9C',
    sospechoso:     'FFFFEB9C',
    medio:          'FFFFD966',
    medium:         'FFFFD966',
    capacidad:      'FFDCE6F1',
    benigna:        'FFC6EFCE',
    bajo:           'FFC6EFCE',
    low:            'FFC6EFCE',
    no_detectado:   'FFF2F2F2',
    si:             'FFFFC7CE',
    posible:        'FFFFEB9C',
  };

  // Cabecera
  const headerRow = ws.addRow(keys);
  headerRow.eachCell(cell => {
    cell.fill      = { type: 'pattern', pattern: 'solid', fgColor: { argb: HEADER_COLOR } };
    cell.font      = { color: { argb: 'FFFFFFFF' }, bold: true };
    cell.alignment = { horizontal: 'center', vertical: 'middle', wrapText: true };
  });
  ws.getRow(1).height = 28;

  // Filas de datos
  for (const row of rows) {
    const r = ws.addRow(keys.map(k => row[k]));

    // Color veredicto_agente
    const vCol  = keys.indexOf('veredicto_agente');
    const vVal  = String(row.veredicto_agente ?? '').toLowerCase();
    if (STATUS_COLORS[vVal] && vCol >= 0) {
      r.getCell(vCol + 1).fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: STATUS_COLORS[vVal] } };
    }

    // Color veredicto_usuario
    const vuCol = keys.indexOf('veredicto_usuario');
    const vuVal = String(row.veredicto_usuario ?? '').toLowerCase();
    if (STATUS_COLORS[vuVal] && vuCol >= 0) {
      r.getCell(vuCol + 1).fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: STATUS_COLORS[vuVal] } };
    }

    // Color columnas de categoría (cat_*)
    for (const key of keys) {
      if (!key.startsWith('cat_')) continue;
      const colIdx = keys.indexOf(key);
      const val    = String(row[key] ?? '').toLowerCase();
      if (STATUS_COLORS[val] && colIdx >= 0) {
        r.getCell(colIdx + 1).fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: STATUS_COLORS[val] } };
      }
    }

    // Color columnas FAQ (faq_*)
    for (const key of keys) {
      if (!key.startsWith('faq_')) continue;
      const colIdx = keys.indexOf(key);
      const val    = String(row[key] ?? '').toLowerCase();
      if (STATUS_COLORS[val] && colIdx >= 0) {
        r.getCell(colIdx + 1).fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: STATUS_COLORS[val] } };
      }
    }
  }

  // Ancho de columnas
  keys.forEach((key, i) => {
    const maxLen = Math.min(
      Math.max(key.length, ...rows.map(r => String(r[key] ?? '').length)),
      60
    );
    ws.getColumn(i + 1).width = maxLen + 2;
  });

  ws.views     = [{ state: 'frozen', xSplit: 0, ySplit: 1 }];
  ws.autoFilter = { from: 'A1', to: `${colLetter(keys.length)}1` };

  // ── Hoja 2: Resumen estadístico ──────────────────────────────────────────
  const ws2       = wb.addWorksheet('Resumen');
  const completed = rows.filter(r => r.estado_job === 'completed');
  const failed    = rows.length - completed.length;

  const countV   = v => completed.filter(r => String(r.veredicto_agente).toLowerCase()  === v).length;
  const countU   = v => completed.filter(r => String(r.veredicto_usuario).toLowerCase() === v).length;
  const countN   = n => completed.filter(r => String(r.nivel_riesgo_agente).toLowerCase() === n).length;
  const countCat = (col, estado) => completed.filter(r => r[col] === estado).length;
  const countFaq = (col, val)    => completed.filter(r => r[col] === val).length;

  const avgDur = completed.length
    ? (completed.reduce((s, r) => s + parseFloat(r.duracion_analisis_s || 0), 0) / completed.length).toFixed(1)
    : 'N/A';

  const addBold = (label, value) => {
    const r = ws2.addRow([label, value]);
    r.getCell(1).font = { bold: true };
    return r;
  };
  const addRow  = (label, value) => ws2.addRow([label, value]);
  const addSep  = () => ws2.addRow([]);

  addBold('Lote', batchLabel);
  addBold('Fecha', new Date().toLocaleString('es-CO'));
  addSep();

  addBold('GENERAL', '');
  addRow('Total extensiones',                  rows.length);
  addRow('Análisis completados',               completed.length);
  addRow('Fallidos / Timeout / Error',         failed);
  addRow('Duración promedio (s)',              avgDur);
  addSep();

  addBold('VEREDICTO AGENTE IA', '');
  addRow('Maliciosa',     countV('maliciosa'));
  addRow('Sospechosa',    countV('sospechosa'));
  addRow('Benigna',       countV('benigna'));
  addRow('Sin veredicto', completed.filter(r => !r.veredicto_agente).length);
  addSep();

  addBold('VEREDICTO USUARIO (agente + determinista)', '');
  addRow('Maliciosa',  countU('maliciosa'));
  addRow('Sospechosa', countU('sospechosa'));
  addRow('Benigna',    countU('benigna'));
  addSep();

  addBold('NIVEL DE RIESGO (Agente)', '');
  addRow('Crítico', countN('critico'));
  addRow('Alto',    countN('alto'));
  addRow('Medio',   countN('medio'));
  addRow('Bajo',    countN('bajo'));
  addSep();

  addBold('CATEGORÍAS DE COMPORTAMIENTO', '');
  const cats = [
    ['cat_acceso_general',           'Acceso general al navegador'],
    ['cat_modificacion_paginas',     'Modificación de páginas'],
    ['cat_lectura_informacion',      'Lectura de información'],
    ['cat_captura_credenciales',     'Captura de credenciales'],
    ['cat_keylogging',               'Keylogging'],
    ['cat_seguimiento_privacidad',   'Seguimiento y privacidad'],
    ['cat_manipulacion_trafico',     'Manipulación de tráfico'],
    ['cat_acceso_historial',         'Acceso a historial'],
    ['cat_descargas_archivos',       'Descargas / archivos'],
    ['cat_abuso_management',         'Abuso de Management API'],
    ['cat_mineria_recursos',         'Minería de recursos (cryptojacking)'],
    ['cat_fingerprinting_severo',    'Fingerprinting severo'],
    ['cat_ofuscacion_transparencia', 'Ofuscación / transparencia'],
  ];
  for (const [col, label] of cats) {
    const crit = countCat(col, 'critico');
    const susp = countCat(col, 'sospechoso');
    const cap  = countCat(col, 'capacidad');
    addRow(label, `critico: ${crit}  sospechoso: ${susp}  capacidad: ${cap}`);
  }
  addSep();

  addBold('RESPUESTAS FAQ (si / posible / no_detectado)', '');
  const faqs = [
    ['faq_puede_capturar_contrasenas',      '¿Puede capturar contraseñas?'],
    ['faq_puede_registrar_teclas',          '¿Puede registrar teclas?'],
    ['faq_puede_espiar_sin_saberlo',        '¿Puede espiar sin saberlo?'],
    ['faq_puede_leer_formularios',          '¿Puede leer formularios?'],
    ['faq_puede_modificar_paginas',         '¿Puede modificar páginas?'],
    ['faq_puede_interceptar_trafico',       '¿Puede interceptar tráfico?'],
    ['faq_puede_ver_paginas_visitadas',     '¿Puede ver páginas visitadas?'],
    ['faq_puede_ver_historial',             '¿Puede ver historial?'],
    ['faq_codigo_oculto_o_sospechoso',      '¿Código oculto o sospechoso?'],
    ['faq_puede_afectar_otras_extensiones', '¿Puede afectar otras extensiones?'],
  ];
  for (const [col, label] of faqs) {
    const si      = countFaq(col, 'si');
    const posible = countFaq(col, 'posible');
    addRow(label, `si: ${si}  posible: ${posible}`);
  }
  addSep();

  addBold('HALLAZGOS ESTÁTICOS (positivos)', '');
  addRow('Críticos totales', completed.reduce((s, r) => s + (parseInt(r.hallazgos_criticos) || 0), 0));
  addRow('Altos totales',    completed.reduce((s, r) => s + (parseInt(r.hallazgos_altos)    || 0), 0));
  addRow('Medios totales',   completed.reduce((s, r) => s + (parseInt(r.hallazgos_medios)   || 0), 0));
  addRow('Bajos totales',    completed.reduce((s, r) => s + (parseInt(r.hallazgos_bajos)    || 0), 0));
  addSep();

  addBold('PERMISOS DECLARADOS PERO NO USADOS', '');
  addRow('Total de permisos no usados',
    completed.reduce((s, r) => s + (parseInt(r.permisos_no_usados_total) || 0), 0));
  addRow('Permisos no usados con riesgo alto/crítico',
    completed.reduce((s, r) => s + (parseInt(r.permisos_no_usados_criticos) || 0), 0));
  addRow('Extensiones con ≥1 permiso no usado',
    completed.filter(r => (parseInt(r.permisos_no_usados_total) || 0) > 0).length);
  addSep();

  addBold('DOMINIOS DETECTADOS', '');
  addRow('Total dominios sensibles (prioridad)',
    completed.reduce((s, r) => s + (parseInt(r.dominios_prioritarios) || 0), 0));
  addRow('Total dominios desconocidos',
    completed.reduce((s, r) => s + (parseInt(r.dominios_desconocidos) || 0), 0));

  ws2.getColumn(1).width = 52;
  ws2.getColumn(2).width = 32;

  await wb.xlsx.writeFile(outPath);
  console.log(`  📊 Excel → ${path.basename(outPath)}`);
}

function colLetter(n) {
  let s = '';
  while (n > 0) {
    n--;
    s = String.fromCharCode(65 + (n % 26)) + s;
    n = Math.floor(n / 26);
  }
  return s;
}

// ── Resumen en consola ───────────────────────────────────────────────────────
function printSummary(rows, label) {
  const completed = rows.filter(r => r.estado_job === 'completed');
  const mal  = completed.filter(r => r.veredicto_agente === 'maliciosa').length;
  const sosp = completed.filter(r => r.veredicto_agente === 'sospechosa').length;
  const ben  = completed.filter(r => r.veredicto_agente === 'benigna').length;
  const avgDur = completed.length
    ? (completed.reduce((s, r) => s + parseFloat(r.duracion_analisis_s || 0), 0) / completed.length).toFixed(1)
    : 'N/A';

  console.log('\n' + '═'.repeat(65));
  console.log(`  RESUMEN — ${label}`);
  console.log('═'.repeat(65));
  console.log(`  Total:               ${rows.length}`);
  console.log(`  Completadas:         ${completed.length}  |  Fallidas: ${rows.length - completed.length}`);
  console.log(`  Maliciosa:           ${mal}`);
  console.log(`  Sospechosa:          ${sosp}`);
  console.log(`  Benigna:             ${ben}`);
  console.log(`  Sin veredicto:       ${completed.filter(r => !r.veredicto_agente).length}`);
  console.log(`  Duración promedio:   ${avgDur}s`);
  console.log('═'.repeat(65));
}

// ── Main ─────────────────────────────────────────────────────────────────────
async function main() {
  const cfg     = parseArgs();
  const baseUrl = cfg.url.replace(/\/$/, '');

  if (!fs.existsSync(cfg.dir)) {
    console.error(`ERROR: Carpeta no encontrada: ${cfg.dir}`);
    process.exit(1);
  }

  const crxFiles = fs.readdirSync(cfg.dir)
    .filter(f => f.toLowerCase().endsWith('.crx'))
    .sort()
    .slice(0, cfg.count)
    .map(f => ({ fullPath: path.join(cfg.dir, f), name: f }));

  if (crxFiles.length === 0) {
    console.error(`ERROR: No hay archivos .crx en ${cfg.dir}`);
    process.exit(1);
  }

  const totalBatches = Math.ceil(crxFiles.length / cfg.batch);
  fs.mkdirSync(cfg.out, { recursive: true });

  console.log('═'.repeat(65));
  console.log('  Extension Warden — Script de Pruebas de Tesis');
  console.log('═'.repeat(65));
  console.log(`  Backend:        ${baseUrl}`);
  console.log(`  Extensiones:    ${crxFiles.length} de ${fs.readdirSync(cfg.dir).filter(f => f.endsWith('.crx')).length} disponibles`);
  console.log(`  Batch size:     ${cfg.batch}  |  Total batches: ${totalBatches}`);
  console.log(`  Timeout/job:    ${MAX_WAIT_MS / 60_000} min`);
  console.log(`  Salida raíz:    ${cfg.out}`);
  console.log('═'.repeat(65));

  process.stdout.write('\nVerificando backend... ');
  if (!(await checkHealth(baseUrl))) {
    console.log('NO DISPONIBLE');
    console.error(`Asegúrate de que el backend esté corriendo en ${baseUrl}`);
    process.exit(1);
  }
  console.log('OK\n');

  const ExcelJS = await loadExcelJS();
  const allRows = [];

  for (let i = 0; i < crxFiles.length; i++) {
    const { fullPath, name } = crxFiles[i];
    const extName     = name.replace(/\.crx$/i, '');
    const batchNum    = Math.floor(i / cfg.batch) + 1;
    const posInBatch  = (i % cfg.batch) + 1;
    const batchLabel  = `Batch ${String(batchNum).padStart(2, '0')} de ${String(totalBatches).padStart(2, '0')}`;
    const batchDir    = path.join(cfg.out, `batch-${String(batchNum).padStart(2, '0')}`);

    fs.mkdirSync(batchDir, { recursive: true });

    console.log(`[${String(i + 1).padStart(3)}/${crxFiles.length}] (${batchLabel}, #${posInBatch}) ${name}`);

    let upload = {}, statusResp = {}, report = null, error = '';
    const t0 = Date.now();

    try {
      process.stdout.write('  ↑ Subiendo... ');
      upload = await uploadExtension(baseUrl, fullPath);
      console.log(`jobId=${upload.jobId}`);

      console.log(`  ⏳ Esperando análisis (máx ${MAX_WAIT_MS / 60_000} min)...`);
      statusResp = await pollStatus(baseUrl, upload.jobId);

      if (statusResp.status === 'completed') {
        report = await getReport(baseUrl, upload.jobId);

        // ── Guardar JSON del job ──────────────────────────────────────────
        const jsonPath = path.join(batchDir, `${upload.jobId}-${extName}.json`);
        fs.writeFileSync(jsonPath, JSON.stringify(report, null, 2), 'utf-8');
        console.log(`  💾 JSON → ${path.relative(cfg.out, jsonPath)}`);

        const a1 = report.agente1 ?? {};
        console.log(
          `  📊 Veredicto agente=${a1.veredicto_global ?? '?'}  ` +
          `Nivel=${a1.nivel_riesgo_inicial ?? '?'}  ` +
          `Veredicto usuario=${report.veredicto_usuario?.veredicto ?? '?'}  ` +
          `Risk score=${report.puntuacion_riesgo?.score ?? '?'} (${report.puntuacion_riesgo?.level ?? '?'})  ` +
          `Permisos no usados=${report.permisos_no_usados?.length ?? 0}`
        );
      } else {
        console.log(`  ❌ Estado final: ${statusResp.status}`);
        if (statusResp.status === 'timeout') error = `timeout tras ${MAX_WAIT_MS / 60_000} min`;
        else error = `job ${statusResp.status}`;
      }
    } catch (e) {
      error = e.message.slice(0, 200);
      console.log(`  💥 ${error}`);
    }

    const elapsedS = (Date.now() - t0) / 1000;
    const row      = buildRow(i + 1, name, upload, statusResp, report, elapsedS, error);
    allRows.push(row);

    // ── Generar Excel al completar el batch (o al terminar) ──────────────
    const isLastInBatch = posInBatch === cfg.batch;
    const isLastOverall = i === crxFiles.length - 1;

    if (isLastInBatch || isLastOverall) {
      const batchRows = allRows.slice((batchNum - 1) * cfg.batch, batchNum * cfg.batch);
      const excelPath = path.join(batchDir, `resultados-batch-${String(batchNum).padStart(2, '0')}.xlsx`);
      printSummary(batchRows, batchLabel);
      await exportBatchExcel(ExcelJS, batchRows, excelPath, batchLabel);
    }

    if (i < crxFiles.length - 1) await sleep(cfg.delay * 1000);
  }

  // ── Resumen final global ─────────────────────────────────────────────────
  printSummary(allRows, `COMPLETO — ${allRows.length} extensiones, ${totalBatches} batches`);
  console.log(`\n✅ Resultados en: ${cfg.out}\n`);
}

main().catch(err => {
  console.error('\nError fatal:', err);
  process.exit(1);
});
