import { Module } from '@nestjs/common';
import { LlmClientService } from './llm/llm-client.service.js';
import { Agent1IntentionService } from './agent1/agent1-intention.service.js';
import { Agent2DynamicService } from './agent2/agent2-dynamic.service.js';
import { AgentsOrchestratorService } from './agents-orchestrator.service.js';
import { StructuredLogger } from '../common/logger/logger.service.js';

/**
 * Agent pipeline (post-refactor):
 *  - Agent 1 = holistic analyst. Receives manifest + static findings + dynamic
 *    observations and produces the final verdict + narratives.
 *  - Agent 2 = dynamic verdict over Stagehand/IntelligentNavigator observations
 *    (originally numbered "Agent 4" before the SAST-per-finding and
 *    domain-abuse-per-finding agents were removed).
 *
 * The previous Agents 2 (SAST) and 3 (domain abuse) were dropped in favour of
 * deterministic static analysis. Domain classification is now done in the
 * static-analysis layer (DomainClassifierService).
 */
@Module({
  providers: [
    StructuredLogger,
    LlmClientService,
    Agent1IntentionService,
    Agent2DynamicService,
    AgentsOrchestratorService,
  ],
  exports: [AgentsOrchestratorService, Agent2DynamicService, LlmClientService],
})
export class AgentsModule {}
