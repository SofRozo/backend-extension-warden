import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { PlatformState } from '../analysis/entities/platform-state.entity.js';
import { PlatformStateService } from './platform-state.service.js';
import { EncryptionService } from '../common/crypto/encryption.service.js';
import { StructuredLogger } from '../common/logger/logger.service.js';

@Module({
  imports: [TypeOrmModule.forFeature([PlatformState])],
  providers: [PlatformStateService, EncryptionService, StructuredLogger],
  exports: [PlatformStateService],
})
export class PlatformStateModule {}
