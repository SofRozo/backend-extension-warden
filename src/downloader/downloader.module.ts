import { Module } from '@nestjs/common';
import { DownloaderService } from './downloader.service.js';
import { StructuredLogger } from '../common/logger/logger.service.js';

@Module({
  providers: [DownloaderService, StructuredLogger],
  exports: [DownloaderService],
})
export class DownloaderModule {}
