import { Module } from '@nestjs/common';
import { ReportService } from './report.service.js';
import { UserRiskSummaryService } from './user-risk/user-risk-summary.service.js';
import { StructuredLogger } from '../common/logger/logger.service.js';

@Module({
  providers: [ReportService, UserRiskSummaryService, StructuredLogger],
  exports: [ReportService],
})
export class ReportModule {}
