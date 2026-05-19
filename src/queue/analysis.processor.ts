import { Processor, WorkerHost } from '@nestjs/bullmq';
import { Job } from 'bullmq';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { AnalysisJob } from '../analysis/entities/analysis-job.entity.js';
import { DownloaderService } from '../downloader/downloader.service.js';
import { PreprocessorService } from '../preprocessor/preprocessor.service.js';
import { StaticAnalysisService } from '../static-analysis/static-analysis.service.js';
import { ReportService } from '../report/report.service.js';
import { AgentsOrchestratorService } from '../agents/agents-orchestrator.service.js';
import { StructuredLogger } from '../common/logger/logger.service.js';
import { AnalysisStatus } from '../common/enums/risk-level.enum.js';
import { ConfigService } from '@nestjs/config';
import type {
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
    private readonly staticAnalysis: StaticAnalysisService,
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
    }>,
  ): Promise<void> {
    const { extensionId, packagePath, jobId } = job.data;
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

      // Step 2: Preprocess + Static Analysis + CWS category (in parallel).
      await this.updateJobStatus(jobId, AnalysisStatus.PREPROCESSING);
      const preprocessTimeoutMs =
        this.config.get<number>('analysis.preprocessTimeoutMs') ?? 180_000;
      const [preprocessed, cwsCategory] = await Promise.all([
        this.withTimeout(
          this.preprocessAndAnalyzeStatic(
            downloadResult.extractPath,
            downloadResult.crxHash,
            jobId,
          ),
          preprocessTimeoutMs,
          'Preprocessing + static analysis timeout (3min exceeded)',
        ),
        this.downloader.fetchCwsCategory(analysisId, jobId),
      ]);
      preprocessed.cwsCategory = cwsCategory;

      await this.jobRepository.update(jobId, {
        extensionName: preprocessed.manifest.name || undefined,
        extensionVersion: preprocessed.manifest.version || undefined,
        crxHash: preprocessed.crxHash,
      });

      // Step 3a: Build UserRiskSummary BEFORE the agent so the 13 evaluated
      // categories can be included in the LLM evidence bundle.
      const preBuilt = this.reportService.buildPreAgentSummary(preprocessed);

      // Step 3b: Agent 1 (holistic static analysis).
      await this.updateJobStatus(jobId, AnalysisStatus.AI_ANALYSIS);
      let agentAnalysis: AgentAnalysisResult;
      try {
        const agentTimeoutMs = Number(
          this.config.get<number>('AGENT_TIMEOUT_MS') ?? 900_000,
        );
        agentAnalysis = await this.withTimeout(
          this.agentsOrchestrator.run(
            preprocessed,
            jobId,
            preBuilt.resumenUsuario,
          ),
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
          ranSuccessfully: false,
          errors: [err instanceof Error ? err.message : String(err)],
        };
      }

      // Step 4: Generate Report (reuse pre-built verdicts to avoid double work)
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
        preprocessed.riskScore,
        preBuilt,
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
