import { Injectable } from '@nestjs/common';
import { Agent1IntentionService } from './agent1/agent1-intention.service.js';
import { Agent2SastService } from './agent2/agent2-sast.service.js';
import { Agent3AbuseService } from './agent3/agent3-abuse.service.js';
import { LlmClientService } from './llm/llm-client.service.js';
import { StructuredLogger } from '../common/logger/logger.service.js';
import type { PreprocessorOutput } from '../common/interfaces/analysis.interfaces.js';
import type {
  AgentAnalysisResult,
  Agent1Output,
  Agent2Output,
} from './interfaces/agents.interfaces.js';

/**
 * Orchestrates Agents 1 → 2 → 3 sequentially.
 *
 * Each agent failure is caught individually so the pipeline degrades
 * gracefully: if Agent 1 fails, Agents 2 and 3 are skipped; if Agent 2
 * fails, Agent 3 is skipped; Agent 3 failure still returns the
 * Agent 1 + 2 results.
 *
 * Returns AgentAnalysisResult.ranSuccessfully=false when any agent
 * failed, but the processor continues — agent outputs are supplementary
 * to the existing rule-based static analysis.
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
    // Skip entirely if no LLM is configured — avoids misleading errors
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
        ranSuccessfully: false,
        errors: ['No LLM configured'],
      };
    }

    const errors: string[] = [];
    let agent1: Agent1Output | null = null;
    let agent2: Agent2Output | null = null;

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
        ranSuccessfully: false,
        errors,
      };
    }

    // ── Agent 2 ──────────────────────────────────────────────────────────────
    try {
      agent2 = await this.agent2.analyze(preprocessed, agent1, jobId);
      this.logger.logWithJob(
        jobId,
        'info',
        `Agent 2 complete: ${agent2.hallazgos.length} findings, ${agent2.dominios_para_playwright.length} domains for Playwright`,
        'AgentsOrchestrator',
      );
    } catch (err) {
      const msg = `Agent 2 failed: ${err instanceof Error ? err.message : String(err)}`;
      errors.push(msg);
      this.logger.logWithJob(jobId, 'error', msg, 'AgentsOrchestrator');
      return {
        agent1,
        agent2: null,
        agent3: null,
        ranSuccessfully: false,
        errors,
      };
    }

    // ── Agent 3 ──────────────────────────────────────────────────────────────
    try {
      const agent3 = await this.agent3.analyze(
        agent1,
        agent2,
        preprocessed.manifest,
        jobId,
      );
      this.logger.logWithJob(
        jobId,
        'info',
        `Agent 3 complete: veredicto=${agent3.veredicto_preliminar}, abusos=${agent3.permisos_abusados.length}`,
        'AgentsOrchestrator',
      );
      return { agent1, agent2, agent3, ranSuccessfully: true, errors };
    } catch (err) {
      const msg = `Agent 3 failed: ${err instanceof Error ? err.message : String(err)}`;
      errors.push(msg);
      this.logger.logWithJob(jobId, 'error', msg, 'AgentsOrchestrator');
      return { agent1, agent2, agent3: null, ranSuccessfully: false, errors };
    }
  }
}
