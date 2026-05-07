import { Module } from '@nestjs/common';
import { PreprocessorService } from './preprocessor.service.js';
import { DeobfuscatorService } from '../static-analysis/deobfuscator/deobfuscator.service.js';
import { StructuredLogger } from '../common/logger/logger.service.js';

@Module({
  providers: [PreprocessorService, DeobfuscatorService, StructuredLogger],
  exports: [PreprocessorService],
})
export class PreprocessorModule {}
