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
import { Agent2DynamicService } from '../agents/agent2/agent2-dynamic.service.js';
import { StructuredLogger } from '../common/logger/logger.service.js';
import { AnalysisStatus } from '../common/enums/risk-level.enum.js';
import { ConfigService } from '@nestjs/config';
import type {
  DynamicAnalysisResult,
  AgentAnalysisResult,
  PreprocessorOutput,
  DynamicVerdictedFinding,
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
    private readonly agent2Dynamic: Agent2DynamicService,
    private readonly staticAnalysis: StaticAnalysisService,
    private readonly dynamicAnalysis: SandboxOrchestratorService,
    private readonly reportService: ReportService,
    private readonly logger: StructuredLogger,
    private readonly config: ConfigService,
  ) {
    super();
  }

  async process(
    job: Job<{
      extensionId?: string;
      packagePath?: string;
      jobId: string;
      navigator?: 'stagehand' | 'intelligent_navigator';
    }>,
  ): Promise<void> {
    const { extensionId, packagePath, jobId, navigator } = job.data;
    const analysisId = extensionId ?? `local-${jobId}`;
    const startTime = Date.now();

    this.logger.logWithJob(
      jobId,
      'info',
      `Processing analysis for extension ${analysisId}`,
      'AnalysisProcessor',
    );

    try {
      // Step 1: Download CRX
      await this.updateJobStatus(jobId, AnalysisStatus.DOWNLOADING);
      const downloadResult = await this.downloader.downloadAndExtract(
        analysisId,
        jobId,
        packagePath,
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

      // Step 3: Dynamic Analysis — visit priority domains. The propósito hint
      // for Stagehand now comes from the manifest directly (description + name)
      // because Agent 1 runs LATER (it needs the dynamic evidence to synthesise
      // the holistic verdict).
      let dynamicResult: DynamicAnalysisResult | null = null;
      await this.updateJobStatus(jobId, AnalysisStatus.DYNAMIC_ANALYSIS);

      const propositoHint = this.buildPropositoHint(preprocessed);

      try {
        const baseDynamicTimeoutMs =
          this.config.get<number>('analysis.dynamicTimeoutMs') || 180000;
        const demoMode = this.config.get<boolean>('demo.enabled') || false;
        const dynamicTimeoutMs = demoMode
          ? baseDynamicTimeoutMs + 210000
          : baseDynamicTimeoutMs;

        dynamicResult = await this.withTimeout(
          this.dynamicAnalysis.executeDynamicAnalysis(
            preprocessed.extractPath,
            analysisId,
            preprocessed.resultado2_priority,
            propositoHint,
            jobId,
            navigator,
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

      // Step 4: Agent 2 (dynamic) — emit per-domain verdict from Stagehand observations.
      let agent2Result: DynamicVerdictedFinding[] = [];
      try {
        const observations = dynamicResult?.domainObservations ?? [];
        agent2Result = await this.withTimeout(
          this.agent2Dynamic.analyze(
            propositoHint,
            preprocessed.resultado2_priority,
            observations,
            jobId,
          ),
          60_000,
          'Agent 2 (dynamic) timeout',
        );
        this.logger.logWithJob(
          jobId,
          'info',
          `Agent 2 (dynamic) complete: ${agent2Result.length} verdicted dynamic findings`,
          'AnalysisProcessor',
        );
      } catch (err) {
        this.logger.logWithJob(
          jobId,
          'warn',
          `Agent 2 (dynamic) skipped: ${err instanceof Error ? err.message : String(err)}`,
          'AnalysisProcessor',
        );
      }

      // Step 5: Agent 1 (holistic). Runs LAST so it sees the full evidence
      // bundle: deterministic static findings + dominio classification +
      // dynamic observations + Agent 2 verdicts. Produces the verdict, risk
      // level, and the narrative arrays the user reads in the report.
      await this.updateJobStatus(jobId, AnalysisStatus.AI_ANALYSIS);
      let agentAnalysis: AgentAnalysisResult;
      try {
        const agentTimeoutMs =
          this.config.get<number>('AGENT_TIMEOUT_MS') ?? 3_600_000;
        agentAnalysis = await this.withTimeout(
          this.agentsOrchestrator.run(preprocessed, jobId, {
            dynamicObservations: dynamicResult?.domainObservations ?? [],
            dynamicVerdicts: agent2Result,
          }),
          agentTimeoutMs,
          'AI analysis timeout exceeded',
        );
      } catch (err) {
        this.logger.logWithJob(
          jobId,
          'warn',
          `AI holistic analysis failed: ${err instanceof Error ? err.message : String(err)}`,
          'AnalysisProcessor',
        );
        agentAnalysis = {
          agent1: null,
          agent2: agent2Result,
          ranSuccessfully: false,
          errors: [err instanceof Error ? err.message : String(err)],
        };
      }

      // Step 6: Generate Report
      await this.updateJobStatus(jobId, AnalysisStatus.GENERATING_REPORT);
      const analysisDuration = Date.now() - startTime;

      const report = this.reportService.generateReport(
        jobId,
        analysisId,
        analysisDuration,
        {
          name: preprocessed.manifest.name || undefined,
          version: preprocessed.manifest.version || undefined,
          author: preprocessed.manifest.author || undefined,
          crxHash: preprocessed.crxHash,
        },
        preprocessed,
        agentAnalysis,
        dynamicResult?.domainObservations ?? [],
        preprocessed.riskScore,
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

      this.downloader.cleanup(analysisId);
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

      this.downloader.cleanup(analysisId);
      throw err;
    }
  }

  /**
   * Builds a short text hint for Stagehand describing what the extension
   * *claims* to do, used to bias the navigator's prompts. Deterministic — no
   * LLM involved. Falls back to a generic instruction when manifest fields are
   * empty.
   */
  private buildPropositoHint(preprocessed: PreprocessorOutput): string {
    const { manifest } = preprocessed;
    const parts: string[] = [];
    if (manifest.name) parts.push(`Nombre: ${manifest.name}`);
    if (manifest.description)
      parts.push(`Descripción: ${manifest.description}`);
    if (manifest.contentScripts.length > 0) {
      const matches = manifest.contentScripts
        .flatMap((cs) => cs.matches)
        .slice(0, 5);
      if (matches.length) parts.push(`Activa en: ${matches.join(', ')}`);
    }
    return (
      parts.join('. ') ||
      'Analizar comportamiento de la extensión (sin descripción declarada)'
    );
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
      if (process.platform === 'win32') {
        execSync(
          'taskkill /F /IM chrome.exe /T & taskkill /F /IM chromium.exe /T & taskkill /F /IM msedge.exe /T',
          { timeout: 5000, stdio: 'ignore' },
        );
      } else {
        execSync('pkill -9 -f chromium || pkill -9 -f chrome || true', {
          timeout: 5000,
        });
      }
      this.logger.logWithJob(
        jobId,
        'warn',
        'Force-killed lingering browser processes',
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
