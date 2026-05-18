import { Injectable } from '@nestjs/common';
import { Agent1IntentionService } from './agent1/agent1-intention.service.js';
import { LlmClientService } from './llm/llm-client.service.js';
import { StructuredLogger } from '../common/logger/logger.service.js';
import type {
  PreprocessorOutput,
  AgentAnalysisResult,
  UserRiskSummaryItem,
} from '../common/interfaces/analysis.interfaces.js';

@Injectable()
export class AgentsOrchestratorService {
  constructor(
    private readonly agent1: Agent1IntentionService,
    private readonly llm: LlmClientService,
    private readonly logger: StructuredLogger,
  ) {}

  async run(
    preprocessed: PreprocessorOutput,
    jobId: string,
    categoriasEvaluadas?: UserRiskSummaryItem[],
  ): Promise<AgentAnalysisResult> {
    if (!this.llm.isConfigured()) {
      this.logger.logWithJob(
        jobId,
        'warn',
        'Agent 1 skipped: no LLM configured (set USAR_OLLAMA=true or GOOGLE_API_KEY)',
        'AgentsOrchestrator',
      );
      return { agent1: null, ranSuccessfully: false, errors: ['No LLM configured'] };
    }

    try {
      const agent1 = await this.agent1.analyze(preprocessed, jobId, categoriasEvaluadas);
      this.logger.logWithJob(
        jobId,
        'info',
        `Agent 1 holistic complete: veredicto=${agent1.veredicto_global}, ` +
          `nivel=${agent1.nivel_riesgo_inicial}, ` +
          `explicacion="${agent1.explicacion.slice(0, 80)}…"`,
        'AgentsOrchestrator',
      );
      return { agent1, ranSuccessfully: true, errors: [] };
    } catch (err) {
      const msg = `Agent 1 failed: ${err instanceof Error ? err.message : String(err)}`;
      this.logger.logWithJob(jobId, 'error', msg, 'AgentsOrchestrator');
      return { agent1: null, ranSuccessfully: false, errors: [msg] };
    }
  }
}
