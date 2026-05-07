/**
 * Script de configuración única para el demo con la profesora.
 *
 * Uso:
 *   npm run demo:setup
 *   npm run demo:setup -- ./mi-carpeta-estados   (ruta personalizada)
 *
 * Abre un Chromium visible. Tú te logueas manualmente en Instagram.
 * Al presionar ENTER, guarda las cookies en disco para uso en el demo.
 * NUNCA compartas ni subas el archivo generado (contiene tu sesión).
 */

import { chromium } from 'playwright';
import * as readline from 'readline';
import * as fs from 'fs';
import * as path from 'path';

const statesDir = path.resolve(process.argv[2] ?? './demo-states');
fs.mkdirSync(statesDir, { recursive: true });

async function main(): Promise<void> {
  console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('  Ext-Sandbox · Configuración de cuenta demo');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
  console.log('Abriendo Chromium...\n');

  const browser = await chromium.launchPersistentContext('', {
    headless: false,
    viewport: { width: 1280, height: 800 },
  });

  const page = await browser.newPage();
  await page.goto('https://www.instagram.com/accounts/login/');

  console.log('────────────────────────────────────────────────');
  console.log('  Inicia sesión en Instagram con tu cuenta de prueba.');
  console.log('  Usa una cuenta DESECHABLE, no tu cuenta personal.');
  console.log('');
  console.log('  Cuando veas tu feed y hayas iniciado sesión del todo,');
  console.log('  vuelve aquí y presiona ENTER.');
  console.log('────────────────────────────────────────────────\n');

  await waitForEnter();

  const statePath = path.join(statesDir, 'instagram.com.json');
  await browser.storageState({ path: statePath });

  console.log(`\n✅ Sesión guardada en: ${statePath}`);
  console.log('\nPara usar en el demo, corre el worker con:');
  console.log(`   DEMO_MODE=true DEMO_STORAGE_STATE_PATH=${statesDir} node dist/main-worker.js\n`);

  await browser.close();
  process.exit(0);
}

function waitForEnter(): Promise<void> {
  return new Promise(resolve => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    rl.question('Presiona ENTER cuando hayas iniciado sesión... ', () => {
      rl.close();
      resolve();
    });
  });
}

main().catch(err => {
  console.error('\n❌ Error:', err);
  process.exit(1);
});
