import { Module } from '@nestjs/common';
import { BullModule } from '@nestjs/bullmq';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AnalysisProcessor, WORKER_QUEUE_NAME } from './analysis.processor.js';
import { AnalysisJob } from '../analysis/entities/analysis-job.entity.js';
import { DownloaderModule } from '../downloader/downloader.module.js';
import { PreprocessorModule } from '../preprocessor/preprocessor.module.js';
import { StaticAnalysisModule } from '../static-analysis/static-analysis.module.js';
import { DynamicAnalysisModule } from '../dynamic-analysis/dynamic-analysis.module.js';
import { ThreatIntelModule } from '../threat-intel/threat-intel.module.js';
import { ReportModule } from '../report/report.module.js';
import { AgentsModule } from '../agents/agents.module.js';
import { StructuredLogger } from '../common/logger/logger.service.js';

// Worker process consumes exactly one queue. WORKER_QUEUE env var picks which:
//   - "analysis"       → headless background (default — used by Docker worker)
//   - "analysis-demo"  → visual DEMO_MODE worker (run on host display)
// Both queues run side by side in Redis, so a Docker worker and a host demo
// worker can serve simultaneously without competing for jobs.
@Module({
  imports: [
    BullModule.registerQueue({
      name: WORKER_QUEUE_NAME,
    }),
    TypeOrmModule.forFeature([AnalysisJob]),
    DownloaderModule,
    PreprocessorModule,
    StaticAnalysisModule,
    DynamicAnalysisModule,
    ThreatIntelModule,
    ReportModule,
    AgentsModule,
  ],
  providers: [AnalysisProcessor, StructuredLogger],
  exports: [BullModule],
})
export class QueueModule {}
