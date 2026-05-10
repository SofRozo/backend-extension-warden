import { Processor, WorkerHost } from '@nestjs/bullmq';
import { Job } from 'bullmq';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { execSync } from 'child_process';
import { AnalysisJob } from '../analysis/entities/analysis-job.entity.js';
import { DownloaderService } from '../downloader/downloader.service.js';
import { PreprocessorService } from '../preprocessor/preprocessor.service.js';
import { StaticAnalysisService } from '../static-analysis/static-analysis.service.js';
import { SandboxOrchestratorService } from '../dynamic-analysis/orchestrator/sandbox-orchestrator.service.js';
import { ReportService } from '../report/report.service.js';
import { AgentsOrchestratorService } from '../agents/agents-orchestrator.service.js';
import { Agent4DynamicService } from '../agents/agent4/agent4-dynamic.service.js';
import { StructuredLogger } from '../common/logger/logger.service.js';
import { AnalysisStatus } from '../common/enums/risk-level.enum.js';
import { ConfigService } from '@nestjs/config';
import type {
  DynamicAnalysisResult,
  AgentAnalysisResult,
  PreprocessorOutput,
} from '../common/interfaces/analysis.interfaces.js';

export const WORKER_QUEUE_NAME =
  process.env.WORKER_QUEUE === 'analysis-demo' ? 'analysis-demo' : 'analysis';

@Processor(WORKER_QUEUE_NAME, {
  concurrency: 5,
  lockDuration: 900000,
})
export class AnalysisProcessor extends WorkerHost {
  constructor(
    @InjectRepository(AnalysisJob)
    private readonly jobRepository: Repository<AnalysisJob>,
    private readonly downloader: DownloaderService,
    private readonly preprocessor: PreprocessorService,
    private readonly agentsOrchestrator: AgentsOrchestratorService,
    private readonly agent4: Agent4DynamicService,
    private readonly staticAnalysis: StaticAnalysisService,
    private readonly dynamicAnalysis: SandboxOrchestratorService,
    private readonly reportService: ReportService,
    private readonly logger: StructuredLogger,
    private readonly config: ConfigService,
  ) {
    super();
  }

  async process(
    job: Job<{ extensionId: string; jobId: string }>,
  ): Promise<void> {
    const { extensionId, jobId } = job.data;
    const startTime = Date.now();

    this.logger.logWithJob(
      jobId,
      'info',
      `Processing analysis for extension ${extensionId}`,
      'AnalysisProcessor',
    );

    try {
      // Step 1: Download CRX
      await this.updateJobStatus(jobId, AnalysisStatus.DOWNLOADING);
      const downloadResult = await this.downloader.downloadAndExtract(
        extensionId,
        jobId,
      );

      // Step 2: Preprocess + Static Analysis (preprocessing fills resultado1
      // and resultado2 in-place via StaticAnalysisService.analyze).
      await this.updateJobStatus(jobId, AnalysisStatus.PREPROCESSING);
      const preprocessTimeoutMs =
        this.config.get<number>('analysis.preprocessTimeoutMs') ?? 180_000;
      const preprocessed = await this.withTimeout(
        this.preprocessAndAnalyzeStatic(
          downloadResult.extractPath,
          downloadResult.crxHash,
          jobId,
        ),
        preprocessTimeoutMs,
        'Preprocessing + static analysis timeout (3min exceeded)',
      );

      await this.jobRepository.update(jobId, {
        extensionName: preprocessed.manifest.name || undefined,
        extensionVersion: preprocessed.manifest.version || undefined,
        crxHash: preprocessed.crxHash,
      });

      // Step 3: Agents 1 → 2 → 3 (static phase). Degrades gracefully when LLM
      // is not configured: agent1/2/3 are returned as null.
      await this.updateJobStatus(jobId, AnalysisStatus.AI_ANALYSIS);
      let agentAnalysis: AgentAnalysisResult;
      try {
        const agentTimeoutMs =
          this.config.get<number>('AGENT_TIMEOUT_MS') ?? 360_000;
        agentAnalysis = await this.withTimeout(
          this.agentsOrchestrator.run(preprocessed, jobId),
          agentTimeoutMs,
          'AI analysis timeout exceeded',
        );
      } catch (err) {
        this.logger.logWithJob(
          jobId,
          'warn',
          `AI static analysis failed: ${err instanceof Error ? err.message : String(err)}`,
          'AnalysisProcessor',
        );
        agentAnalysis = {
          agent1: null,
          agent2: null,
          agent3: null,
          agent4: null,
          ranSuccessfully: false,
          errors: [err instanceof Error ? err.message : String(err)],
        };
      }

      // Step 4: Dynamic Analysis — visit priority domains
      let dynamicResult: DynamicAnalysisResult | null = null;
      await this.updateJobStatus(jobId, AnalysisStatus.DYNAMIC_ANALYSIS);

      try {
        const baseDynamicTimeoutMs =
          this.config.get<number>('analysis.dynamicTimeoutMs') || 180000;
        const demoMode = this.config.get<boolean>('demo.enabled') || false;
        const dynamicTimeoutMs = demoMode
          ? baseDynamicTimeoutMs + 210000
          : baseDynamicTimeoutMs;

        const proposito =
          agentAnalysis.agent1?.proposito ??
          'Analizar comportamiento de la extensión';

        dynamicResult = await this.withTimeout(
          this.dynamicAnalysis.executeDynamicAnalysis(
            preprocessed.extractPath,
            extensionId,
            preprocessed.resultado2_priority,
            proposito,
            jobId,
          ),
          dynamicTimeoutMs,
          'Dynamic analysis timeout (RNF02: 180s exceeded)',
        );
      } catch (err) {
        this.logger.logWithJob(
          jobId,
          'warn',
          `Dynamic analysis skipped/failed: ${err instanceof Error ? err.message : String(err)}`,
          'AnalysisProcessor',
        );
        this.forceKillBrowserProcesses(jobId);
      }

      // Step 5: Agent 4 — emit per-domain verdict and replicate it on each
      // priority finding so resultado_dinamico has one entry per priority
      // discovery.
      try {
        const proposito =
          agentAnalysis.agent1?.proposito ??
          'Analizar comportamiento de la extensión';
        const observations = dynamicResult?.domainObservations ?? [];
        const agent4Result = await this.withTimeout(
          this.agent4.analyze(
            proposito,
            preprocessed.resultado2_priority,
            observations,
            jobId,
          ),
          60_000,
          'Agent 4 timeout',
        );
        agentAnalysis = { ...agentAnalysis, agent4: agent4Result };
        this.logger.logWithJob(
          jobId,
          'info',
          `Agent 4 complete: ${agent4Result.length} verdicted dynamic findings`,
          'AnalysisProcessor',
        );
      } catch (err) {
        this.logger.logWithJob(
          jobId,
          'warn',
          `Agent 4 skipped: ${err instanceof Error ? err.message : String(err)}`,
          'AnalysisProcessor',
        );
      }

      // Step 6: Generate Report
      await this.updateJobStatus(jobId, AnalysisStatus.GENERATING_REPORT);
      const analysisDuration = Date.now() - startTime;

      const report = this.reportService.generateReport(
        jobId,
        extensionId,
        analysisDuration,
        {
          name: preprocessed.manifest.name || undefined,
          version: preprocessed.manifest.version || undefined,
          author: preprocessed.manifest.author || undefined,
          crxHash: preprocessed.crxHash,
        },
        agentAnalysis,
        dynamicResult?.domainObservations ?? [],
      );

      // Strip U+0000 (PostgreSQL JSONB rejects null bytes)
      const safeReport = JSON.parse(
        JSON.stringify(report).replace(/\\u0000/g, ''),
      ) as Record<string, unknown>;

      await this.jobRepository.update(jobId, {
        status: AnalysisStatus.COMPLETED,
        report: safeReport as any,
        analysisDurationMs: analysisDuration,
      });

      this.logger.logWithJob(
        jobId,
        'info',
        `Analysis completed: duration=${analysisDuration}ms`,
        'AnalysisProcessor',
      );

      this.downloader.cleanup(extensionId);
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : String(err);
      this.logger.logWithJob(
        jobId,
        'error',
        `Analysis failed: ${errorMessage}`,
        'AnalysisProcessor',
      );

      await this.jobRepository.update(jobId, {
        status: AnalysisStatus.FAILED,
        errorMessage,
      });

      this.downloader.cleanup(extensionId);
      throw err;
    }
  }

  private async preprocessAndAnalyzeStatic(
    extractPath: string,
    crxHash: string,
    jobId: string,
  ): Promise<PreprocessorOutput> {
    const preprocessed = await this.preprocessor.preprocess(
      extractPath,
      crxHash,
      jobId,
    );
    await this.staticAnalysis.analyze(preprocessed, jobId);
    return preprocessed;
  }

  private async updateJobStatus(
    jobId: string,
    status: AnalysisStatus,
  ): Promise<void> {
    await this.jobRepository.update(jobId, { status });
  }

  private forceKillBrowserProcesses(jobId: string): void {
    try {
      execSync('pkill -9 -f chromium || pkill -9 -f chrome || true', {
        timeout: 5000,
      });
      this.logger.logWithJob(
        jobId,
        'warn',
        'Force-killed lingering browser processes (SIGKILL)',
        'AnalysisProcessor',
      );
    } catch {
      /* best effort */
    }
  }

  private async withTimeout<T>(
    promise: Promise<T>,
    timeoutMs: number,
    errorMessage: string,
  ): Promise<T> {
    let timer: ReturnType<typeof setTimeout>;
    const timeout = new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new Error(errorMessage)), timeoutMs);
    });
    try {
      return await Promise.race([promise, timeout]);
    } finally {
      clearTimeout(timer!);
    }
  }
}
