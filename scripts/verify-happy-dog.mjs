#!/usr/bin/env node
// Ad-hoc verification: run preprocessor + static-analysis + user-risk-summary
// directly against the Happy Dog extension folder, and print the user-facing
// results. Used to confirm the cascade of fixes detects:
//   - scripting.executeScript({ files: ["a", "b"] }) → both files mapped
//   - main.js / breedSpriteCache.js → reclassified to content_script
//   - chrome.tabs.onUpdated, chrome.scripting.executeScript → real API usage
//   - innerHTML, createElement, fetch → AST findings reach the evaluators

import pkg1 from '../dist/src/preprocessor/preprocessor.service.js';
import pkg2 from '../dist/src/static-analysis/static-analysis.service.js';
import pkg3 from '../dist/src/static-analysis/ast-parser/ast-parser.service.js';
import pkg4 from '../dist/src/static-analysis/domain-classifier.service.js';
import pkg5 from '../dist/src/report/user-risk/user-risk-summary.service.js';
import pkg6 from '../dist/src/static-analysis/deobfuscator/deobfuscator.service.js';

const { PreprocessorService } = pkg1;
const { StaticAnalysisService } = pkg2;
const { AstParserService } = pkg3;
const { DomainClassifierService } = pkg4;
const { UserRiskSummaryService } = pkg5;
const { DeobfuscatorService } = pkg6;

const fakeLogger = {
  info: () => {},
  warn: () => {},
  error: () => {},
  debug: () => {},
  log: () => {},
  logWithJob: () => {},
};

const EXT_PATH =
  'C:/Users/sofro/OneDrive/Desktop/cdoblkdcnbcdlcfklmbmkapbekgfbijp/cdoblkdcnbcdlcfklmbmkapbekgfbijp/2.37.1_0';

async function main() {
  const deob = new DeobfuscatorService(fakeLogger);
  const preprocessor = new PreprocessorService(deob, fakeLogger);
  const ast = new AstParserService(fakeLogger);
  const domains = new DomainClassifierService(fakeLogger);
  const staticAnalysis = new StaticAnalysisService(ast, domains, fakeLogger);
  const userRisk = new UserRiskSummaryService();

  console.log('▶ Preprocessing', EXT_PATH);
  const pre = await preprocessor.preprocess(EXT_PATH, 'happy-dog-hash', 'verify-job');

  console.log('\n=== ROLE ASSIGNMENT ===');
  for (const f of pre.files) {
    console.log(`  ${f.role.padEnd(14)} ${f.path}`);
  }

  console.log('\n=== DEPENDENCY GRAPH EDGES (scripting/injection) ===');
  for (const e of pre.dependencyGraph.edges) {
    if (e.type === 'scripting_executeScript' || e.type === 'script_injection') {
      console.log(`  ${e.type.padEnd(28)} ${e.from} → ${e.to} (line ${e.line})`);
    }
  }

  console.log('\n▶ Running static analysis');
  await staticAnalysis.analyze(pre, 'verify-job');

  console.log('\n=== POSITIVE STATIC FINDINGS ===');
  const positives = pre.resultado1.filter(
    (f) => (f.confidence ?? 0) >= 0.7,
  );
  console.log(`Total positives: ${positives.length}`);
  for (const f of positives.slice(0, 25)) {
    console.log(
      `  [${(f.confidence ?? 0).toFixed(2)}] ${f.discoveryType.padEnd(30)} ${f.filePath}:${f.line}  ${f.detail.slice(0, 60)}`,
    );
  }
  if (positives.length > 25)
    console.log(`  ... +${positives.length - 25} more`);

  console.log('\n=== DOMAINS DISCOVERED ===');
  console.log(`Priority: ${pre.resultado2_priority.length}`);
  for (const d of pre.resultado2_priority)
    console.log(`  [${d.category}] ${d.domain}  (${d.filePath}:${d.line})`);
  console.log(`Unknown: ${pre.resultado2_unknown.length}`);
  for (const d of pre.resultado2_unknown.slice(0, 10))
    console.log(`  [${d.category}] ${d.domain}  (${d.filePath}:${d.line})`);

  console.log('\n▶ Running user-risk summary');
  const verdicted = pre.resultado1.map((f) => ({
    ...f,
    veredicto: (f.confidence ?? 0) >= 0.7 ? 'positivo' : 'falso_positivo',
    razon: f.why ?? '',
  }));
  const domainVerdicted = [
    ...pre.resultado2_priority,
    ...pre.resultado2_unknown,
  ].map((f) => ({
    ...f,
    veredicto: 'positivo',
    razon: `Categoría ${f.category}`,
  }));
  const summary = userRisk.buildSummary(pre, verdicted, domainVerdicted, []);
  const verdict = userRisk.buildVerdict(summary);

  console.log('\n=== VEREDICTO USUARIO ===');
  console.log(`  Nivel:      ${verdict.nivel}`);
  console.log(`  Veredicto:  ${verdict.veredicto}`);
  console.log(`  Resumen:    ${verdict.resumen}`);
  console.log(`  Razones:`);
  for (const r of verdict.razones) console.log(`    • ${r}`);

  console.log('\n=== 10 CATEGORÍAS ===');
  for (const item of summary) {
    const colored =
      item.estado === 'critico'
        ? '🔴'
        : item.estado === 'sospechoso'
          ? '🟠'
          : item.estado === 'capacidad'
            ? '🔵'
            : '⚪';
    console.log(`\n${colored} [${item.estado.toUpperCase()}] ${item.titulo}`);
    console.log(`   ${item.resumen}`);
    for (const ev of item.evidencias) console.log(`   · ${ev}`);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
