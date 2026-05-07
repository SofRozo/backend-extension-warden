import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { BullModule } from '@nestjs/bullmq';
import { HealthController } from './health.controller.js';
import { AnalysisJob } from '../analysis/entities/analysis-job.entity.js';

@Module({
  imports: [
    TypeOrmModule.forFeature([AnalysisJob]),
    BullModule.registerQueue({ name: 'analysis' }),
  ],
  controllers: [HealthController],
})
export class HealthModule {}
