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
import { ThreatIntelService } from '../threat-intel/threat-intel.service.js';
import { ReportService } from '../report/report.service.js';
import { AgentsOrchestratorService } from '../agents/agents-orchestrator.service.js';
import { Agent4DynamicService } from '../agents/agent4/agent4-dynamic.service.js';
import { StructuredLogger } from '../common/logger/logger.service.js';
import { AnalysisStatus } from '../common/enums/risk-level.enum.js';
import { ConfigService } from '@nestjs/config';
import type {
  DynamicAnalysisResult,
  AgentAnalysisResult,
} from '../common/interfaces/analysis.interfaces.js';

/**
 * Queue this worker process consumes. Picked at module-load time from the
 * WORKER_QUEUE env var so a single binary can serve either the headless
 * background queue ("analysis") or the visual demo queue ("analysis-demo").
 * Exported so QueueModule can register the matching BullModule producer.
 */
export const WORKER_QUEUE_NAME =
  process.env.WORKER_QUEUE === 'analysis-demo' ? 'analysis-demo' : 'analysis';

@Processor(WORKER_QUEUE_NAME, {
  concurrency: 5,
  // RNF02: Total pipeline timeout — forced termination if exceeded.
  // 15 min ceiling covers demo mode (180s + 210s) + static 60s + overhead.
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
    private readonly threatIntel: ThreatIntelService,
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

      // Step 2: Preprocess — hard failure if the extension is invalid.
      // Throws synchronously on missing/unparseable manifest; the outer catch
      // marks the job FAILED and does NOT retry (the file itself is invalid).
      await this.updateJobStatus(jobId, AnalysisStatus.PREPROCESSING);
      const preprocessed = await this.preprocessor.preprocess(
        downloadResult.extractPath,
        downloadResult.crxHash,
        jobId,
      );

      // Persist extension metadata now that we have it from the manifest
      await this.jobRepository.update(jobId, {
        extensionName: preprocessed.manifest.name || undefined,
        extensionVersion: preprocessed.manifest.version || undefined,
        crxHash: preprocessed.crxHash,
      });

      // Step 3: AI Analysis — Agents 1, 2, 3 (optional, degrades gracefully)
      await this.updateJobStatus(jobId, AnalysisStatus.AI_ANALYSIS);
      let agentAnalysis: AgentAnalysisResult | undefined;
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
          `AI analysis skipped: ${err instanceof Error ? err.message : String(err)}`,
          'AnalysisProcessor',
        );
      }

      // Step 4: Static Analysis (RNF02 — max 60s)
      await this.updateJobStatus(jobId, AnalysisStatus.STATIC_ANALYSIS);
      const staticTimeoutMs =
        this.config.get<number>('analysis.staticTimeoutMs') || 60000;
      const staticResult = await this.withTimeout(
        this.staticAnalysis.analyze(preprocessed, jobId),
        staticTimeoutMs,
        'Static analysis timeout (RNF02: 60s exceeded)',
      );

      // Step 4: Dynamic Analysis (RNF02 — max 180s, demo adds 210s)
      let dynamicResult: DynamicAnalysisResult | null = null;
      await this.updateJobStatus(jobId, AnalysisStatus.DYNAMIC_ANALYSIS);

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
            extensionId,
            staticResult,
            jobId,
            agentAnalysis,
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

      // Step 4.5: Agent 4 — Dynamic Log Analysis
      // Called after dynamic analysis if Stagehand/navigator produced domain
      // observations AND Agent 1 ran (we need the extension's stated purpose).
      if (dynamicResult?.domainObservations?.length && agentAnalysis?.agent1) {
        try {
          const veredictoEstatico =
            agentAnalysis.agent3?.veredicto_preliminar ?? 'sospechosa';
          const agent4 = await this.withTimeout(
            this.agent4.analyze(
              agentAnalysis.agent1.proposito,
              veredictoEstatico,
              dynamicResult.domainObservations,
              jobId,
            ),
            30_000,
            'Agent 4 timeout',
          );
          agentAnalysis = { ...agentAnalysis, agent4 };
          this.logger.logWithJob(
            jobId,
            'info',
            `Agent 4 complete: veredicto_dinamico=${agent4.veredicto_dinamico}, confirma_estatico=${agent4.confirma_hallazgos_estaticos}`,
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
      }

      // Step 5: Threat Intelligence
      await this.updateJobStatus(jobId, AnalysisStatus.THREAT_INTEL);

      const staticDomains = staticResult.discoveredDomains
        .filter((d) => d.source === 'code')
        .map((d) => d.domain);

      const dynamicDomains = (dynamicResult?.evidence.networkRequests ?? [])
        .filter((r) => r.origin === 'extension' && r.url.startsWith('http'))
        .map((r) => {
          try {
            return new URL(r.url).hostname;
          } catch {
            return null;
          }
        })
        .filter((h): h is string => !!h);

      const isLikelyDomain = (d: string) => {
        const domainRe =
          /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$/i;
        const staticAssets =
          /\.(png|jpg|jpeg|gif|css|json|js|svg|woff2?|map|crx)$/i;
        return domainRe.test(d) && !staticAssets.test(d);
      };

      const domainsToQuery = [
        ...new Set([...staticDomains, ...dynamicDomains]),
      ].filter(isLikelyDomain);

      let threatIntelResults: any[] = [];
      try {
        threatIntelResults = await this.threatIntel.queryDomains(
          domainsToQuery,
          jobId,
        );
      } catch (err) {
        this.logger.logWithJob(
          jobId,
          'warn',
          `Threat intel failed (degraded mode): ${err instanceof Error ? err.message : String(err)}`,
          'AnalysisProcessor',
        );
      }

      // Step 6: Generate Report
      await this.updateJobStatus(jobId, AnalysisStatus.GENERATING_REPORT);
      const analysisDuration = Date.now() - startTime;

      const report = this.reportService.generateReport(
        jobId,
        extensionId,
        staticResult,
        dynamicResult,
        threatIntelResults,
        analysisDuration,
        {
          name: preprocessed.manifest.name || undefined,
          version: preprocessed.manifest.version || undefined,
          author: preprocessed.manifest.author || undefined,
        },
        agentAnalysis,
      );

      // Step 7: Persist report
      // Use parameterized update — avoids raw SQL string construction issues with JSONB.
      // Strip U+0000 escape sequences first: PostgreSQL JSONB rejects null bytes even
      // when properly JSON-encoded as  .
      const safeReport = JSON.parse(
        JSON.stringify(report).replace(/\\u0000/g, ''),
      ) as Record<string, unknown>;

      await this.jobRepository.update(jobId, {
        status: AnalysisStatus.COMPLETED,
        overallRisk: report.overallRisk,
        report: safeReport as any,
        confidence: report.confidence,
        analysisDurationMs: analysisDuration,
      });

      this.logger.logWithJob(
        jobId,
        'info',
        `Analysis completed: risk=${report.overallRisk}, confidence=${report.confidence.toFixed(2)}, duration=${analysisDuration}ms`,
        'AnalysisProcessor',
      );

      // Step 8: Cleanup (§11 — in-memory analysis principle)
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

  private async updateJobStatus(
    jobId: string,
    status: AnalysisStatus,
  ): Promise<void> {
    await this.jobRepository.update(jobId, { status });
  }

  /**
   * RNF02: Force-kill lingering browser/chromium processes after timeout.
   */
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
      // Best effort — process may already be dead
    }
  }

  /**
   * RNF02: Timeout with forced termination guarantee.
   */
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
