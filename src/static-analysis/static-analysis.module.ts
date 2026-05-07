import { Module } from '@nestjs/common';
import { StaticAnalysisService } from './static-analysis.service.js';
import { AstParserService } from './ast-parser/ast-parser.service.js';
import { DomainDiscoveryService } from './domain-discovery/domain-discovery.service.js';
import { DeobfuscatorService } from './deobfuscator/deobfuscator.service.js';
import { StructuredLogger } from '../common/logger/logger.service.js';

@Module({
  providers: [
    StaticAnalysisService,
    AstParserService,
    DomainDiscoveryService,
    DeobfuscatorService,
    StructuredLogger,
  ],
  exports: [StaticAnalysisService, DomainDiscoveryService, DeobfuscatorService],
})
export class StaticAnalysisModule {}
