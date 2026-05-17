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
const MAX_WAIT_MS      = 720_000; // 12 min — cubre runs lentos de LLM

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

// ── Extraer métricas del reporte (API actual) ────────────────────────────────
function buildRow(index, filename, upload, statusResp, report, elapsedS, error = '') {
  if (!report) {
    return {
      '#':                       index,
      archivo:                   filename,
      job_id:                    upload?.jobId ?? '',
      estado_job:                statusResp?.status ?? 'unknown',
      // Agente 1
      veredicto_agente:          '',
      nivel_riesgo_agente:       '',
      categoria_agente:          '',
      proposito:                 '',
      explicacion:               '',
      // Veredicto usuario (determinista)
      veredicto_usuario:         '',
      nivel_usuario:             '',
      resumen_usuario:           '',
      razones_usuario:           '',
      // Risk score
      risk_score:                '',
      risk_level:                '',
      // Hallazgos estáticos
      hallazgos_positivos_total: '',
      hallazgos_criticos:        '',
      hallazgos_altos:           '',
      hallazgos_medios:          '',
      hallazgos_bajos:           '',
      // Categorías de comportamiento (resumen_usuario)
      acceso_general:            '',
      modificacion_paginas:      '',
      lectura_informacion:       '',
      captura_credenciales:      '',
      keylogging:                '',
      seguimiento_privacidad:    '',
      manipulacion_trafico:      '',
      abuso_management:          '',
      // Dominios y dinámica
      dominios_prioritarios:     '',
      dominios_desconocidos:     '',
      stagehand_errores:         '',
      // Tiempos
      duracion_analisis_s:       elapsedS.toFixed(1),
      error,
    };
  }

  const agente1   = report.agente1   ?? {};
  const estructura = report.estructura ?? {};
  const resultado1 = estructura.resultado1 ?? [];
  const prio       = estructura.resultado2_priority ?? [];
  const unknown    = estructura.resultado2_unknown  ?? [];
  const dinamico   = estructura.resultado_dinamico  ?? [];
  const navDoms    = report.navegacionDominios ?? [];
  const verdUsuario = report.veredicto_usuario ?? {};
  const riskScore  = report.puntuacion_riesgo  ?? {};
  const resumenUsr = report.resumen_usuario    ?? [];

  // Hallazgos estáticos positivos
  const positivos = resultado1.filter(f => f.veredicto === 'positivo');
  const bySev     = sev => positivos.filter(f => f.severity === sev).length;

  // Estado por categoría de comportamiento (resumen_usuario)
  const catStatus = id => {
    const item = resumenUsr.find(c => c.id === id);
    return item ? item.estado : 'no_detectado';
  };

  // Stagehand errors
  const stagehandErrors = navDoms.filter(n => n.error).length;

  return {
    '#':                       index,
    archivo:                   filename,
    job_id:                    upload?.jobId ?? '',
    estado_job:                statusResp?.status ?? 'unknown',
    // Agente 1
    veredicto_agente:          agente1.veredicto_global ?? '',
    nivel_riesgo_agente:       agente1.nivel_riesgo_inicial ?? '',
    categoria_agente:          agente1.categoria ?? '',
    proposito:                 (agente1.proposito ?? '').slice(0, 150),
    explicacion:               (agente1.explicacion ?? '').slice(0, 300),
    // Veredicto determinista (UserRiskSummaryService)
    veredicto_usuario:         verdUsuario.veredicto ?? '',
    nivel_usuario:             verdUsuario.nivel     ?? '',
    resumen_usuario:           (verdUsuario.resumen  ?? '').slice(0, 200),
    razones_usuario:           (verdUsuario.razones  ?? []).join(' | ').slice(0, 300),
    // Risk score
    risk_score:                riskScore.score ?? '',
    risk_level:                riskScore.level ?? '',
    // Hallazgos estáticos (solo positivos)
    hallazgos_positivos_total: positivos.length,
    hallazgos_criticos:        bySev('critical'),
    hallazgos_altos:           bySev('high'),
    hallazgos_medios:          bySev('medium'),
    hallazgos_bajos:           bySev('low'),
    // 10 categorías de comportamiento
    acceso_general:            catStatus('acceso_general_navegador'),
    modificacion_paginas:      catStatus('modificacion_paginas'),
    lectura_informacion:       catStatus('lectura_informacion'),
    captura_credenciales:      catStatus('captura_credenciales'),
    keylogging:                catStatus('keylogging'),
    seguimiento_privacidad:    catStatus('seguimiento_privacidad'),
    manipulacion_trafico:      catStatus('manipulacion_trafico'),
    abuso_management:          catStatus('abuso_management'),
    // Dominios
    dominios_prioritarios:     prio.length,
    dominios_desconocidos:     unknown.length,
    stagehand_errores:         stagehandErrors,
    // Tiempo
    duracion_analisis_s:       elapsedS.toFixed(1),
    error,
  };
}

// ── Excel (un archivo por batch) ─────────────────────────────────────────────
async function loadExcelJS() {
  try {
    // Intenta desde node_modules del backend
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
    medio:          'FFFFD966',
    medium:         'FFFFD966',
    benigna:        'FFC6EFCE',
    bajo:           'FFC6EFCE',
    low:            'FFC6EFCE',
    no_detectado:   'FFF2F2F2',
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
    const r     = ws.addRow(keys.map(k => row[k]));
    // Color por veredicto_agente
    const vCol  = keys.indexOf('veredicto_agente');
    const vVal  = String(row.veredicto_agente ?? '').toLowerCase();
    const color = STATUS_COLORS[vVal];
    if (color && vCol >= 0) {
      r.getCell(vCol + 1).fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: color } };
    }
    // Color por veredicto_usuario
    const vuCol = keys.indexOf('veredicto_usuario');
    const vuVal = String(row.veredicto_usuario ?? '').toLowerCase();
    const vuColor = STATUS_COLORS[vuVal];
    if (vuColor && vuCol >= 0) {
      r.getCell(vuCol + 1).fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: vuColor } };
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

  const countV = v => completed.filter(r => String(r.veredicto_agente).toLowerCase() === v).length;
  const countU = v => completed.filter(r => String(r.veredicto_usuario).toLowerCase() === v).length;
  const countN = n => completed.filter(r => String(r.nivel_riesgo_agente).toLowerCase() === n).length;
  const countCat = (col, estado) => completed.filter(r => r[col] === estado).length;

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
  addRow('Total extensiones',                   rows.length);
  addRow('Análisis completados',                completed.length);
  addRow('Fallidos / Timeout / Error',          failed);
  addRow('Duración promedio (s)',               avgDur);
  addSep();
  addBold('VEREDICTO AGENTE IA', '');
  addRow('Maliciosa',   countV('maliciosa'));
  addRow('Sospechosa',  countV('sospechosa'));
  addRow('Benigna',     countV('benigna'));
  addRow('Sin veredicto', completed.filter(r => !r.veredicto_agente).length);
  addSep();
  addBold('VEREDICTO DETERMINISTA (usuario)', '');
  addRow('Maliciosa',   countU('maliciosa'));
  addRow('Sospechosa',  countU('sospechosa'));
  addRow('Benigna',     countU('benigna'));
  addSep();
  addBold('NIVEL DE RIESGO (Agente)', '');
  addRow('Crítico', countN('critico'));
  addRow('Alto',    countN('alto'));
  addRow('Medio',   countN('medio'));
  addRow('Bajo',    countN('bajo'));
  addSep();
  addBold('CATEGORÍAS DE COMPORTAMIENTO (critico/sospechoso)', '');
  const cats = [
    ['acceso_general',         'Acceso general al navegador'],
    ['modificacion_paginas',   'Modificación de páginas'],
    ['lectura_informacion',    'Lectura de información'],
    ['captura_credenciales',   'Captura de credenciales'],
    ['keylogging',             'Keylogging'],
    ['seguimiento_privacidad', 'Seguimiento y privacidad'],
    ['manipulacion_trafico',   'Manipulación de tráfico'],
    ['abuso_management',       'Abuso de Management API'],
  ];
  for (const [col, label] of cats) {
    const crit = countCat(col, 'critico');
    const susp = countCat(col, 'sospechoso');
    addRow(label, `critico: ${crit}  sospechoso: ${susp}`);
  }
  addSep();
  addBold('HALLAZGOS ESTÁTICOS (positivos)', '');
  addRow('Críticos totales', completed.reduce((s, r) => s + (parseInt(r.hallazgos_criticos) || 0), 0));
  addRow('Altos totales',    completed.reduce((s, r) => s + (parseInt(r.hallazgos_altos) || 0), 0));
  addRow('Medios totales',   completed.reduce((s, r) => s + (parseInt(r.hallazgos_medios) || 0), 0));
  addRow('Bajos totales',    completed.reduce((s, r) => s + (parseInt(r.hallazgos_bajos) || 0), 0));

  ws2.getColumn(1).width = 45;
  ws2.getColumn(2).width = 30;

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
  console.log(`  Salida raíz:    ${cfg.out}`);
  console.log('═'.repeat(65));

  process.stdout.write('\nVerificando backend... ');
  if (!(await checkHealth(baseUrl))) {
    console.log('NO DISPONIBLE');
    console.error(`Asegúrate de que el backend esté corriendo en ${baseUrl}`);
    process.exit(1);
  }
  console.log('OK\n');

  const ExcelJS  = await loadExcelJS();
  const allRows  = [];

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

      console.log(`  ⏳ Esperando análisis (máx ${MAX_WAIT_MS / 1000}s)...`);
      statusResp = await pollStatus(baseUrl, upload.jobId);

      if (statusResp.status === 'completed') {
        report = await getReport(baseUrl, upload.jobId);

        // ── Guardar JSON del job ──────────────────────────────────────────
        const jsonPath = path.join(batchDir, `${upload.jobId}-${extName}.json`);
        fs.writeFileSync(jsonPath, JSON.stringify(report, null, 2), 'utf-8');
        console.log(`  💾 JSON → ${path.relative(cfg.out, jsonPath)}`);

        const a1 = report.agente1 ?? {};
        console.log(`  📊 Veredicto agente=${a1.veredicto_global ?? '?'}  Nivel=${a1.nivel_riesgo_inicial ?? '?'}  ` +
                    `Veredicto usuario=${report.veredicto_usuario?.veredicto ?? '?'}`);
      } else {
        console.log(`  ❌ Estado final: ${statusResp.status}`);
        if (statusResp.status === 'timeout') error = `timeout tras ${MAX_WAIT_MS / 1000}s`;
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
      const batchRows  = allRows.slice((batchNum - 1) * cfg.batch, batchNum * cfg.batch);
      const excelPath  = path.join(batchDir, `resultados-batch-${String(batchNum).padStart(2, '0')}.xlsx`);
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
