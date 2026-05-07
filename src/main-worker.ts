/**
 * Worker Entry Point — Ext-Sandbox
 *
 * Corre como proceso separado del API (Container 3 — sandbox_net).
 * No expone ningún puerto HTTP. Solo procesa trabajos de la cola Redis (BullMQ).
 *
 * Arquitectura (§8):
 *   - Lee jobs de Redis (accesible desde sandbox_net)
 *   - Ejecuta análisis dinámico con Playwright (sandboxed con seccomp + non-root)
 *   - Escribe resultados a PostgreSQL vía la red de datos compartida
 *
 * Diferencia con main.ts (API):
 *   - Sin ValidationPipe ni server HTTP
 *   - Sin módulos de análisis de queue del lado API
 *   - createApplicationContext en lugar de create (sin HTTP)
 */
import { NestFactory } from '@nestjs/core';
import { WorkerModule } from './worker.module.js';
import { StructuredLogger } from './common/logger/logger.service.js';
import { WORKER_QUEUE_NAME } from './queue/analysis.processor.js';

async function bootstrap() {
  const logger = new StructuredLogger();

  // ApplicationContext = NestJS sin servidor HTTP
  const app = await NestFactory.createApplicationContext(WorkerModule, {
    logger,
  });

  const demoMode = process.env.DEMO_MODE === 'true';
  logger.log(
    `Ext-Sandbox Worker started — consuming queue "${WORKER_QUEUE_NAME}"` +
      (demoMode ? ' [DEMO_MODE: visible browser]' : ' [headless]'),
    'WorkerBootstrap',
  );

  // Graceful shutdown
  process.on('SIGTERM', async () => {
    logger.log('SIGTERM received — shutting down worker gracefully...', 'WorkerBootstrap');
    await app.close();
    process.exit(0);
  });

  process.on('SIGINT', async () => {
    logger.log('SIGINT received — shutting down worker gracefully...', 'WorkerBootstrap');
    await app.close();
    process.exit(0);
  });
}

bootstrap().catch((err) => {
  console.error('Worker bootstrap failed:', err);
  process.exit(1);
});
