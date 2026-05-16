/**
 * Script de pruebas — Extension Warden (Tesis de grado)
 *
 * Envía extensiones .crx al backend, espera los resultados y exporta
 * un CSV incremental + un Excel por batch para el documento de grado.
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
 *   --out    Carpeta de salida        (default: ./resultados)
 *   --count  Total de extensiones     (default: 50)
 *   --batch  Extensiones por Excel    (default: 10)
 *   --delay  Segundos entre envíos    (default: 2)
 *
 * Requiere Node 18+.
 * Para Excel: npm install exceljs  (en esta misma carpeta)
 */

import fs   from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ── Configuración por defecto ────────────────────────────────────────────────
const DEFAULTS = {
  url:   'http://localhost:3000',
  dir:   path.join(__dirname, '..', '..', 'Malicious Browser Extensions'),
  out:   path.join(__dirname, 'resultados'),
  count: 50,
  batch: 10,
  delay: 2,
};
const POLL_INTERVAL_MS = 6_000;
const MAX_WAIT_MS      = 360_000;
const DETECTED_RISKS   = new Set(['critical', 'high', 'medium']);

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

// ── Helpers HTTP ─────────────────────────────────────────────────────────────
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
  let lastStatus = 'unknown';
  while (Date.now() < deadline) {
    await sleep(POLL_INTERVAL_MS);
    try {
      const r    = await fetch(`${baseUrl}/status/${jobId}`, { signal: AbortSignal.timeout(15_000) });
      const data = await r.json();
      lastStatus = data.status ?? 'unknown';
      const prog = data.progress ?? 0;
      process.stdout.write(`    → [${String(prog).padStart(3)}%] ${lastStatus}       \r`);
      if (lastStatus === 'completed' || lastStatus === 'failed') {
        process.stdout.write('\n');
        return data;
      }
    } catch (e) {
      process.stdout.write(`\n    ! Error al consultar estado: ${e.message}\n`);
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

// ── Construir fila de resultados ─────────────────────────────────────────────
function buildRow(index, filename, upload, status, report, elapsedS, error = '') {
  const privacyLabels  = report?.privacyLabels  ?? [];
  const staticFindings = report?.staticFindings ?? [];
  const contactedUrls  = report?.contactedUrls  ?? [];
  const urlRep         = report?.contactedUrlsReputation ?? [];
  const threatIntel    = report?.threatIntelResults ?? [];

  const maliciousUrls  = urlRep.filter(u => u?.malicious).length;
  const threatDetected = threatIntel.filter(t => t?.detected).length;
  const overallRisk    = report?.overallRisk ?? status?.overallRisk ?? '';
  const confidence     = report?.confidence  ?? '';
  const durationMs     = report?.analysisDuration ?? '';
  const recommendation = (report?.recommendation ?? '').slice(0, 250);

  const privCategories = privacyLabels.map(l => l?.category ?? '').filter(Boolean).join(', ');
  const privSeverities = privacyLabels.map(l => l?.severity ?? '').filter(Boolean).join(', ');
  const detected       = DETECTED_RISKS.has(overallRisk?.toLowerCase());

  return {
    '#':                      index,
    filename,
    extension_id:             upload?.extensionId ?? '',
    job_id:                   upload?.jobId       ?? '',
    upload_status:            upload?.jobId ? 'ok' : 'error',
    analysis_status:          status?.status ?? 'unknown',
    overall_risk:             overallRisk,
    confidence,
    detected_malicious:       detected ? 'SÍ' : 'NO',
    analysis_duration_ms:     durationMs,
    total_elapsed_s:          elapsedS.toFixed(1),
    privacy_labels_count:     privacyLabels.length,
    privacy_categories:       privCategories,
    privacy_severities:       privSeverities,
    static_findings_count:    staticFindings.length,
    contacted_urls_count:     contactedUrls.length,
    malicious_urls_count:     maliciousUrls,
    threat_detections:        threatDetected,
    recommendation,
    error,
  };
}

// ── CSV ──────────────────────────────────────────────────────────────────────
function escapeCSV(val) {
  const s = String(val ?? '');
  if (s.includes(',') || s.includes('"') || s.includes('\n'))
    return `"${s.replace(/"/g, '""')}"`;
  return s;
}
function rowToCsv(row, keys) {
  return keys.map(k => escapeCSV(row[k])).join(',');
}

// ── Excel ────────────────────────────────────────────────────────────────────
async function loadExcelJS() {
  try {
    return (await import('exceljs')).default;
  } catch {
    return null;
  }
}

async function exportExcel(ExcelJS, rows, outPath, label) {
  if (!ExcelJS) {
    console.log('  (exceljs no encontrado — solo CSV. Instala: npm install exceljs)');
    return;
  }

  const wb = new ExcelJS.Workbook();

  // ── Hoja 1: Datos detallados ─────────────────────────────────────────────
  const ws = wb.addWorksheet('Resultados Detallados');

  const RISK_COLORS = {
    critical:      { argb: 'FFFF4C4C' },
    high:          { argb: 'FFFF9933' },
    medium:        { argb: 'FFFFD966' },
    low:           { argb: 'FF70AD47' },
    informational: { argb: 'FFBDD7EE' },
    none:          { argb: 'FFF2F2F2' },
  };
  const HEADER_COLOR = { argb: 'FF1F4E79' };

  const keys = Object.keys(rows[0] ?? {});
  const headerRow = ws.addRow(keys);
  headerRow.eachCell(cell => {
    cell.fill      = { type: 'pattern', pattern: 'solid', fgColor: HEADER_COLOR };
    cell.font      = { color: { argb: 'FFFFFFFF' }, bold: true };
    cell.alignment = { horizontal: 'center' };
  });

  for (const row of rows) {
    const r     = ws.addRow(keys.map(k => row[k]));
    const risk  = String(row.overall_risk ?? '').toLowerCase();
    const st    = String(row.analysis_status ?? '').toLowerCase();
    const color = RISK_COLORS[risk] ?? (
      ['failed', 'timeout', 'error'].includes(st) ? { argb: 'FFBFBFBF' } : null
    );
    if (color) r.eachCell(cell => { cell.fill = { type: 'pattern', pattern: 'solid', fgColor: color }; });
  }

  keys.forEach((key, i) => {
    const col    = ws.getColumn(i + 1);
    const maxLen = Math.min(Math.max(key.length, ...rows.map(r => String(r[key] ?? '').length)), 60);
    col.width    = maxLen + 3;
  });
  ws.views     = [{ state: 'frozen', ySplit: 1 }];
  ws.autoFilter = { from: 'A1', to: `${String.fromCharCode(64 + keys.length)}1` };

  // ── Hoja 2: Resumen estadístico ──────────────────────────────────────────
  const ws2      = wb.addWorksheet('Resumen');
  const total    = rows.length;
  const completed = rows.filter(r => r.analysis_status === 'completed').length;
  const failed   = total - completed;
  const detected = rows.filter(r => r.detected_malicious === 'SÍ').length;

  const byRisk = {};
  for (const r of rows) {
    const k = r.overall_risk || 'N/A';
    byRisk[k] = (byRisk[k] ?? 0) + 1;
  }

  const validDur    = rows.map(r => Number(r.analysis_duration_ms)).filter(n => n > 0);
  const avgMs       = validDur.length ? validDur.reduce((a, b) => a + b, 0) / validDur.length : 0;
  const validElap   = rows.map(r => Number(r.total_elapsed_s)).filter(n => n > 0);
  const avgElapsed  = validElap.length ? validElap.reduce((a, b) => a + b, 0) / validElap.length : 0;
  const detRate     = completed ? `${((detected / completed) * 100).toFixed(1)}%` : 'N/A';

  const summaryRows = [
    ['Lote', label],
    ['Métrica', 'Valor'],
    ['Total extensiones en este lote',        total],
    ['Análisis completados',                  completed],
    ['Análisis fallidos / timeout',           failed],
    ['Extensiones detectadas como maliciosas', detected],
    ['Tasa de detección (%)',                 detRate],
    ['', ''],
    ['Distribución por nivel de riesgo', ''],
    ...Object.entries(byRisk).sort().map(([k, v]) => [`  ${k}`, v]),
    ['', ''],
    ['Duración promedio del análisis (ms)',   avgMs.toFixed(0)],
    ['Duración promedio del análisis (seg)',  (avgMs / 1000).toFixed(1)],
    ['Tiempo total promedio por extensión (s)', avgElapsed.toFixed(1)],
    ['', ''],
    ['Fecha de prueba', new Date().toLocaleString('es-CO')],
  ];

  for (const [lbl, value] of summaryRows) {
    const r = ws2.addRow([lbl, value]);
    if (lbl === 'Métrica' || lbl === 'Lote') {
      r.getCell(1).font = { bold: true, size: 12 };
      r.getCell(2).font = { bold: true, size: 12 };
    }
  }
  ws2.getColumn(1).width = 45;
  ws2.getColumn(2).width = 20;

  await wb.xlsx.writeFile(outPath);
  console.log(`  Excel guardado: ${path.basename(outPath)}`);
}

// ── Resumen en consola ───────────────────────────────────────────────────────
function printSummary(rows, label = 'Total') {
  const total     = rows.length;
  const completed = rows.filter(r => r.analysis_status === 'completed').length;
  const detected  = rows.filter(r => r.detected_malicious === 'SÍ').length;
  const byRisk    = {};
  for (const r of rows) {
    const k = r.overall_risk || 'N/A';
    byRisk[k] = (byRisk[k] ?? 0) + 1;
  }
  const validDur = rows.map(r => Number(r.analysis_duration_ms)).filter(n => n > 0);
  const avgMs    = validDur.length ? validDur.reduce((a, b) => a + b, 0) / validDur.length : 0;

  console.log('\n' + '='.repeat(65));
  console.log(`  RESUMEN — ${label}`);
  console.log('='.repeat(65));
  console.log(`  Total probadas:          ${total}`);
  console.log(`  Análisis completados:    ${completed}`);
  console.log(`  Análisis fallidos:       ${total - completed}`);
  console.log(`  Detectadas maliciosas:   ${detected}`);
  console.log(completed
    ? `  Tasa de detección:       ${((detected / completed) * 100).toFixed(1)}%`
    : `  Tasa de detección:       N/A`);
  console.log(`  Duración promedio:       ${(avgMs / 1000).toFixed(1)}s por extensión`);
  console.log('\n  Distribución por riesgo:');
  for (const [risk, cnt] of Object.entries(byRisk).sort()) {
    console.log(`    ${risk.padEnd(15)} ${String(cnt).padStart(3)}  ${'█'.repeat(Math.min(cnt, 40))}`);
  }
  console.log('='.repeat(65));
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
    .map(f => path.join(cfg.dir, f));

  if (crxFiles.length === 0) {
    console.error(`ERROR: No hay archivos .crx en ${cfg.dir}`);
    process.exit(1);
  }

  const totalBatches = Math.ceil(crxFiles.length / cfg.batch);
  fs.mkdirSync(cfg.out, { recursive: true });

  const ts      = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  const csvPath = path.join(cfg.out, `resultados_${ts}.csv`);

  console.log('='.repeat(65));
  console.log('  Extension Warden — Script de Pruebas de Tesis');
  console.log('='.repeat(65));
  console.log(`  Backend:      ${baseUrl}`);
  console.log(`  Extensiones:  ${crxFiles.length}`);
  console.log(`  Batch size:   ${cfg.batch} extensiones por Excel`);
  console.log(`  Total batches:${totalBatches}`);
  console.log(`  CSV único:    ${csvPath}`);
  console.log('='.repeat(65));

  process.stdout.write('\nVerificando backend... ');
  if (!(await checkHealth(baseUrl))) {
    console.log('NO DISPONIBLE');
    console.log(`Asegúrate de que el backend esté corriendo en ${baseUrl}`);
    process.exit(1);
  }
  console.log('OK');

  const KEYS = [
    '#', 'filename', 'extension_id', 'job_id',
    'upload_status', 'analysis_status', 'overall_risk', 'confidence',
    'detected_malicious', 'analysis_duration_ms', 'total_elapsed_s',
    'privacy_labels_count', 'privacy_categories', 'privacy_severities',
    'static_findings_count', 'contacted_urls_count',
    'malicious_urls_count', 'threat_detections',
    'recommendation', 'error',
  ];

  const ExcelJS    = await loadExcelJS();
  const csvStream  = fs.createWriteStream(csvPath, { encoding: 'utf8' });
  csvStream.write(KEYS.join(',') + '\n');

  const allRows    = [];   // todos los resultados (para el CSV)
  let   batchRows  = [];   // solo el batch actual

  for (let i = 0; i < crxFiles.length; i++) {
    const filePath   = crxFiles[i];
    const filename   = path.basename(filePath);
    const batchNum   = Math.floor(i / cfg.batch) + 1;
    const posInBatch = (i % cfg.batch) + 1;

    console.log(`\n[${String(i + 1).padStart(2)}/${crxFiles.length}] (Lote ${batchNum}/${totalBatches}, #${posInBatch}) ${filename}`);

    let upload = {}, status = {}, report = null, error = '';
    const t0 = Date.now();

    try {
      process.stdout.write('    Subiendo... ');
      upload = await uploadExtension(baseUrl, filePath);
      console.log(`jobId=${upload.jobId}`);

      console.log(`    Esperando análisis (máx ${MAX_WAIT_MS / 1000}s)...`);
      status = await pollStatus(baseUrl, upload.jobId);

      if (status.status === 'completed') {
        try {
          report = await getReport(baseUrl, upload.jobId);
          const risk = report.overallRisk ?? '?';
          const conf = report.confidence  ?? '?';
          const dur  = report.analysisDuration ?? '?';
          console.log(`    Riesgo: ${risk.toUpperCase().padEnd(8)}  Confianza: ${conf}  Duración: ${dur}ms`);
        } catch (e) {
          error = `reporte_error: ${e.message}`;
          console.log(`    ! No se pudo obtener reporte: ${e.message}`);
        }
      } else {
        console.log(`    Estado final: ${status.status}`);
        if (status.status === 'timeout') error = `timeout tras ${MAX_WAIT_MS / 1000}s`;
      }
    } catch (e) {
      error = e.message.slice(0, 200);
      console.log(`    ! ${error}`);
    }

    const elapsed = (Date.now() - t0) / 1000;
    const row     = buildRow(i + 1, filename, upload, status, report, elapsed, error);
    allRows.push(row);
    batchRows.push(row);
    csvStream.write(rowToCsv(row, KEYS) + '\n');

    // ── Guardar Excel al completar cada batch ────────────────────────────────
    const isLastInBatch  = posInBatch === cfg.batch;
    const isLastOverall  = i === crxFiles.length - 1;

    if (isLastInBatch || isLastOverall) {
      const batchLabel   = `Lote ${String(batchNum).padStart(2, '0')} de ${String(totalBatches).padStart(2, '0')}`;
      const batchXlsx    = path.join(
        cfg.out,
        `batch_${String(batchNum).padStart(2, '0')}_de_${String(totalBatches).padStart(2, '0')}_${ts}.xlsx`
      );
      console.log(`\n  → Guardando Excel del ${batchLabel}...`);
      printSummary(batchRows, batchLabel);
      await exportExcel(ExcelJS, batchRows, batchXlsx, batchLabel);
      batchRows = [];   // resetear para el siguiente batch
    }

    if (i < crxFiles.length - 1) await sleep(cfg.delay * 1000);
  }

  csvStream.end();
  console.log(`\n  CSV completo: ${csvPath}`);

  // ── Resumen final de todo el run ─────────────────────────────────────────
  printSummary(allRows, `COMPLETO (${allRows.length} extensiones, ${totalBatches} lotes)`);

  console.log('\nPruebas finalizadas.');
}

main().catch(err => {
  console.error('\nError fatal:', err);
  process.exit(1);
});
