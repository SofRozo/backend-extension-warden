import { Module } from '@nestjs/common';
import { ThreatIntelService } from './threat-intel.service.js';
import { StructuredLogger } from '../common/logger/logger.service.js';

@Module({
  providers: [ThreatIntelService, StructuredLogger],
  exports: [ThreatIntelService],
})
export class ThreatIntelModule {}
