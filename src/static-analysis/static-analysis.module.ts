import { Module } from '@nestjs/common';
import { StaticAnalysisService } from './static-analysis.service.js';
import { AstParserService } from './ast-parser/ast-parser.service.js';
import { DeobfuscatorService } from './deobfuscator/deobfuscator.service.js';
import { DomainClassifierService } from './domain-classifier.service.js';
import { StructuredLogger } from '../common/logger/logger.service.js';

@Module({
  providers: [
    StaticAnalysisService,
    AstParserService,
    DeobfuscatorService,
    DomainClassifierService,
    StructuredLogger,
  ],
  exports: [
    StaticAnalysisService,
    DeobfuscatorService,
    DomainClassifierService,
  ],
})
export class StaticAnalysisModule {}
