import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { BullModule } from '@nestjs/bullmq';
import { ScheduleModule } from '@nestjs/schedule';
import { ThrottlerModule, ThrottlerGuard } from '@nestjs/throttler';
import { APP_GUARD } from '@nestjs/core';
import configuration from './config/configuration.js';
import { AnalysisModule } from './analysis/analysis.module.js';
import { HealthModule } from './health/health.module.js';
import { PlatformStateModule } from './platform-state/platform-state.module.js';
import { AnalysisJob } from './analysis/entities/analysis-job.entity.js';
import { PlatformState } from './analysis/entities/platform-state.entity.js';
import { RetentionService } from './database/retention.service.js';
import { StructuredLogger } from './common/logger/logger.service.js';
import { EncryptionService } from './common/crypto/encryption.service.js';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      load: [configuration],
    }),
    // §11: Schedule module for data retention cron jobs + §9.1 honeypot renewal
    ScheduleModule.forRoot(),
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
        synchronize: true, // Set to false in production; use migrations
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
          // RNF01: Redis con autenticación (contraseña en .env / secreto de Docker)
          password: config.get<string>('redis.password') || undefined,
        },
      }),
    }),
    // RNF03: Rate limiting — max 20 requests / 60 segundos por IP
    ThrottlerModule.forRoot([
      {
        name: 'short',
        ttl: 10000, // 10 segundos
        limit: 5, // max 5 req en 10s (burst protection)
      },
      {
        name: 'medium',
        ttl: 60000, // 60 segundos
        limit: 20, // max 20 req/min por IP
      },
    ]),
    TypeOrmModule.forFeature([AnalysisJob]),
    AnalysisModule,
    HealthModule,
    PlatformStateModule,
  ],
  providers: [
    RetentionService,
    StructuredLogger,
    EncryptionService,
    // RNF03: Aplicar rate limiting globalmente a todos los endpoints
    {
      provide: APP_GUARD,
      useClass: ThrottlerGuard,
    },
  ],
})
export class AppModule {}
