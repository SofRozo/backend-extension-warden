import {
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  ServiceUnavailableException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { InjectQueue } from '@nestjs/bullmq';
import { Queue } from 'bullmq';
import { AnalysisJob } from '../analysis/entities/analysis-job.entity.js';

@Controller('health')
export class HealthController {
  constructor(
    @InjectRepository(AnalysisJob)
    private readonly jobRepository: Repository<AnalysisJob>,
    @InjectQueue('analysis')
    private readonly analysisQueue: Queue,
  ) {}

  /**
   * RNF05: Liveness probe — is the process alive?
   * Checked every 60 seconds by Docker.
   */
  @Get()
  @HttpCode(HttpStatus.OK)
  check() {
    return {
      status: 'ok',
      timestamp: new Date().toISOString(),
      service: 'ext-sandbox',
      uptime: process.uptime(),
      memory: process.memoryUsage(),
    };
  }

  /**
   * RNF05: Readiness probe — can the service handle requests?
   * Verifies PostgreSQL and Redis connectivity before accepting traffic.
   */
  @Get('ready')
  async ready() {
    const checks: Record<string, 'up' | 'down'> = {
      database: 'down',
      redis: 'down',
    };

    // Check PostgreSQL
    try {
      await this.jobRepository.query('SELECT 1');
      checks.database = 'up';
    } catch {
      // Database is down
    }

    // Check Redis (via BullMQ queue connection)
    try {
      const client = await this.analysisQueue.client;
      const pong = await client.ping();
      checks.redis = pong === 'PONG' ? 'up' : 'down';
    } catch {
      // Redis is down
    }

    const allHealthy = Object.values(checks).every((v) => v === 'up');

    if (!allHealthy) {
      throw new ServiceUnavailableException({
        status: 'unavailable',
        timestamp: new Date().toISOString(),
        checks,
      });
    }

    return {
      status: 'ready',
      timestamp: new Date().toISOString(),
      checks,
    };
  }
}
