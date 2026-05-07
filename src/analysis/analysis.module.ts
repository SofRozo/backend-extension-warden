import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { BullModule } from '@nestjs/bullmq';
import { AnalysisController } from './analysis.controller.js';
import { AnalysisService } from './analysis.service.js';
import { AnalysisJob } from './entities/analysis-job.entity.js';
import { StructuredLogger } from '../common/logger/logger.service.js';

@Module({
  imports: [
    TypeOrmModule.forFeature([AnalysisJob]),
    BullModule.registerQueue(
      { name: 'analysis' },        // headless / background (Docker worker)
      { name: 'analysis-demo' },   // visual demo (host worker with DEMO_MODE=true)
    ),
  ],
  controllers: [AnalysisController],
  providers: [AnalysisService, StructuredLogger],
  exports: [AnalysisService],
})
export class AnalysisModule {}
