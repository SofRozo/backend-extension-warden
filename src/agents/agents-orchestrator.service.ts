import { Injectable } from '@nestjs/common';
import { Agent1IntentionService } from './agent1/agent1-intention.service.js';
import { Agent2SastService } from './agent2/agent2-sast.service.js';
import { Agent3AbuseService } from './agent3/agent3-abuse.service.js';
import { LlmClientService } from './llm/llm-client.service.js';
import { StructuredLogger } from '../common/logger/logger.service.js';
import type { PreprocessorOutput } from '../common/interfaces/analysis.interfaces.js';
import type {
  AgentAnalysisResult,
  VerdictedStaticFinding,
} from '../common/interfaces/analysis.interfaces.js';
import type { Agent1Output } from './interfaces/agents.interfaces.js';

/**
 * Orchestrates Agents 1 → 2 → 3 (static phase). Agent 4 runs separately after
 * the dynamic analysis. Each agent failure is caught individually so the
 * pipeline degrades gracefully.
 */
@Injectable()
export class AgentsOrchestratorService {
  constructor(
    private readonly agent1: Agent1IntentionService,
    private readonly agent2: Agent2SastService,
    private readonly agent3: Agent3AbuseService,
    private readonly llm: LlmClientService,
    private readonly logger: StructuredLogger,
  ) {}

  async run(
    preprocessed: PreprocessorOutput,
    jobId: string,
  ): Promise<AgentAnalysisResult> {
    if (!this.llm.isConfigured()) {
      this.logger.logWithJob(
        jobId,
        'warn',
        'Agents skipped: no LLM configured (set USAR_OLLAMA=true or GOOGLE_API_KEY)',
        'AgentsOrchestrator',
      );
      return {
        agent1: null,
        agent2: null,
        agent3: null,
        agent4: null,
        ranSuccessfully: false,
        errors: ['No LLM configured'],
      };
    }

    const errors: string[] = [];
    let agent1: Agent1Output | null = null;
    let agent2: VerdictedStaticFinding[] | null = null;

    // ── Agent 1 ──────────────────────────────────────────────────────────────
    try {
      agent1 = await this.agent1.analyze(preprocessed, jobId);
      this.logger.logWithJob(
        jobId,
        'info',
        `Agent 1 complete: proposito="${agent1.proposito.slice(0, 80)}", riesgo=${agent1.nivel_riesgo_inicial}`,
        'AgentsOrchestrator',
      );
    } catch (err) {
      const msg = `Agent 1 failed: ${err instanceof Error ? err.message : String(err)}`;
      errors.push(msg);
      this.logger.logWithJob(jobId, 'error', msg, 'AgentsOrchestrator');
      return {
        agent1: null,
        agent2: null,
        agent3: null,
        agent4: null,
        ranSuccessfully: false,
        errors,
      };
    }

    // ── Agent 2 (resultado1 1:1) ─────────────────────────────────────────────
    try {
      agent2 = await this.agent2.analyze(preprocessed, agent1, jobId);
      this.logger.logWithJob(
        jobId,
        'info',
        `Agent 2 complete: ${agent2.length} findings evaluated (${agent2.filter((f) => f.veredicto === 'positivo').length} positivos)`,
        'AgentsOrchestrator',
      );
    } catch (err) {
      const msg = `Agent 2 failed: ${err instanceof Error ? err.message : String(err)}`;
      errors.push(msg);
      this.logger.logWithJob(jobId, 'error', msg, 'AgentsOrchestrator');
    }

    // ── Agent 3 (resultado2 priority + unknown) ──────────────────────────────
    try {
      const agent3Out = await this.agent3.analyze(
        agent1,
        preprocessed.resultado2_priority,
        preprocessed.resultado2_unknown,
        jobId,
      );
      this.logger.logWithJob(
        jobId,
        'info',
        `Agent 3 complete: ${agent3Out.priority.length} priority + ${agent3Out.unknown.length} unknown evaluados`,
        'AgentsOrchestrator',
      );
      return {
        agent1,
        agent2,
        agent3: agent3Out,
        agent4: null,
        ranSuccessfully: errors.length === 0,
        errors,
      };
    } catch (err) {
      const msg = `Agent 3 failed: ${err instanceof Error ? err.message : String(err)}`;
      errors.push(msg);
      this.logger.logWithJob(jobId, 'error', msg, 'AgentsOrchestrator');
      return {
        agent1,
        agent2,
        agent3: null,
        agent4: null,
        ranSuccessfully: false,
        errors,
      };
    }
  }
}
