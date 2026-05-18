import { Module } from '@nestjs/common';
import { LlmClientService } from './llm/llm-client.service.js';
import { Agent1IntentionService } from './agent1/agent1-intention.service.js';
import { AgentsOrchestratorService } from './agents-orchestrator.service.js';
import { StructuredLogger } from '../common/logger/logger.service.js';

@Module({
  providers: [
    StructuredLogger,
    LlmClientService,
    Agent1IntentionService,
    AgentsOrchestratorService,
  ],
  exports: [AgentsOrchestratorService, LlmClientService],
})
export class AgentsModule {}
