import { Module } from '@nestjs/common';
import { ReportService } from './report.service.js';
import { StructuredLogger } from '../common/logger/logger.service.js';

@Module({
  providers: [ReportService, StructuredLogger],
  exports: [ReportService],
})
export class ReportModule {}
