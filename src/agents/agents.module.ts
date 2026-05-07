import { Module } from '@nestjs/common';
import { LlmClientService } from './llm/llm-client.service.js';
import { DomainClassifierService } from './agent2/domain-classifier.service.js';
import { Agent1IntentionService } from './agent1/agent1-intention.service.js';
import { Agent2SastService } from './agent2/agent2-sast.service.js';
import { Agent3AbuseService } from './agent3/agent3-abuse.service.js';
import { Agent4DynamicService } from './agent4/agent4-dynamic.service.js';
import { AgentsOrchestratorService } from './agents-orchestrator.service.js';
import { StructuredLogger } from '../common/logger/logger.service.js';
import { ThreatIntelModule } from '../threat-intel/threat-intel.module.js';

@Module({
  imports: [ThreatIntelModule],
  providers: [
    StructuredLogger,
    LlmClientService,
    DomainClassifierService,
    Agent1IntentionService,
    Agent2SastService,
    Agent3AbuseService,
    Agent4DynamicService,
    AgentsOrchestratorService,
  ],
  exports: [AgentsOrchestratorService, Agent4DynamicService, LlmClientService],
})
export class AgentsModule {}
