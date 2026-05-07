import { Module } from '@nestjs/common';
import { SandboxOrchestratorService } from './orchestrator/sandbox-orchestrator.service.js';
import { NetworkInterceptorService } from './network-interceptor/network-interceptor.service.js';
import { DetonationStrategyService } from './detonation-strategies/detonation-strategy.service.js';
import { IntelligentNavigatorService } from './navigator/intelligent-navigator.service.js';
import { StagehandService } from './navigator/stagehand.service.js';
import { StructuredLogger } from '../common/logger/logger.service.js';

@Module({
  providers: [
    SandboxOrchestratorService,
    NetworkInterceptorService,
    DetonationStrategyService,
    IntelligentNavigatorService,
    StagehandService,
    StructuredLogger,
  ],
  exports: [SandboxOrchestratorService],
})
export class DynamicAnalysisModule {}
