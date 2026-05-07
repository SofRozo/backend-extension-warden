/**
 * WorkerModule — módulo mínimo para el Container 3 (Worker Sandbox).
 *
 * Incluye SOLO lo necesario para procesar la cola de análisis:
 *   - Configuración
 *   - TypeORM (para persistir resultados)
 *   - BullMQ (para consumir jobs de Redis)
 *   - QueueModule (contiene el AnalysisProcessor)
 *
 * NO incluye:
 *   - HealthModule (sin HTTP)
 *   - AnalysisModule (sin endpoint REST)
 *   - ScheduleModule (los crons corren solo en el API)
 *
 * Nota de seguridad (§8, RNF01):
 *   El aislamiento de red se garantiza a nivel de Docker (sandbox_net).
 *   El proceso Node.js sí tiene acceso a la BD para escribir resultados.
 *   El navegador Chromium está aislado dentro del proceso por Playwright +
 *   seccomp profile + usuario non-root (sandboxuser).
 */
import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { BullModule } from '@nestjs/bullmq';
import configuration from './config/configuration.js';
import { QueueModule } from './queue/queue.module.js';
import { AgentsModule } from './agents/agents.module.js';
import { AnalysisJob } from './analysis/entities/analysis-job.entity.js';
import { PlatformState } from './analysis/entities/platform-state.entity.js';
import { StructuredLogger } from './common/logger/logger.service.js';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      load: [configuration],
    }),
    TypeOrmModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        type: 'postgres' as const,
        host: config.get<string>('database.host'),
        port: config.get<number>('database.port'),
        username: config.get<string>('database.username'),
        password: config.get<string>('database.password'),
        database: config.get<string>('database.name'),
        entities: [AnalysisJob, PlatformState],
        synchronize: false, // Worker no modifica schema — solo el API lo hace
        logging: false,
      }),
    }),
    BullModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        connection: {
          host: config.get<string>('redis.host'),
          port: config.get<number>('redis.port'),
          password: config.get<string>('redis.password') || undefined,
        },
      }),
    }),
    QueueModule,
    AgentsModule,
  ],
  providers: [StructuredLogger],
})
export class WorkerModule {}
