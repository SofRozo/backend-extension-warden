import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { ConfigService } from '@nestjs/config';
import { AnalysisProcessor } from '../analysis.processor.js';
import { AnalysisJob } from '../../analysis/entities/analysis-job.entity.js';
import { DownloaderService } from '../../downloader/downloader.service.js';
import { PreprocessorService } from '../../preprocessor/preprocessor.service.js';
import { AgentsOrchestratorService } from '../../agents/agents-orchestrator.service.js';
import { Agent4DynamicService } from '../../agents/agent4/agent4-dynamic.service.js';
import { StaticAnalysisService } from '../../static-analysis/static-analysis.service.js';
import { SandboxOrchestratorService } from '../../dynamic-analysis/orchestrator/sandbox-orchestrator.service.js';
import { ThreatIntelService } from '../../threat-intel/threat-intel.service.js';
import { ReportService } from '../../report/report.service.js';
import { StructuredLogger } from '../../common/logger/logger.service.js';
import { AnalysisStatus, RiskLevel } from '../../common/enums/risk-level.enum.js';

describe('AnalysisProcessor', () => {
  let processor: AnalysisProcessor;
  let mockRepository: any;
  let mockDownloader: any;
  let mockStatic: any;
  let mockDynamic: any;
  let mockThreatIntel: any;
  let mockReport: any;

  const mockStaticResult = {
    findings: [],
    discoveredDomains: [],
    domSelectors: [],
    manifestPermissions: [],
    manifestHostPermissions: [],
    crxHash: 'abc123',
    obfuscationDetected: false,
    deobfuscationApplied: false,
  };

  const mockReportOutput = {
    overallRisk: RiskLevel.INFORMATIONAL,
    confidence: 0.9,
    privacyLabels: [],
    staticFindings: [],
    threatIntelResults: [],
    contactedUrls: [],
    abusedPermissions: [],
    recommendation: 'Safe',
  };

  beforeEach(async () => {
    const mockQB = {
      update: jest.fn().mockReturnThis(),
      set: jest.fn().mockReturnThis(),
      where: jest.fn().mockReturnThis(),
      execute: jest.fn().mockResolvedValue({ affected: 1 }),
    };

    mockRepository = {
      update: jest.fn().mockResolvedValue({ affected: 1 }),
      createQueryBuilder: jest.fn().mockReturnValue(mockQB),
    };

    mockDownloader = {
      downloadAndExtract: jest.fn().mockResolvedValue({
        crxPath: '/tmp/ext.crx',
        extractPath: '/tmp/extracted/ext',
        crxHash: 'abc123',
        manifestData: { name: 'Test Ext', version: '1.0' },
      }),
      cleanup: jest.fn(),
    };

    mockStatic = {
      analyze: jest.fn().mockResolvedValue(mockStaticResult),
    };

    mockDynamic = {
      executeDynamicAnalysis: jest.fn().mockResolvedValue({
        strategy: 'passive_trigger',
        evidence: { networkRequests: [], domMutations: [], keyboardEvents: [] },
        duration: 5000,
        timedOut: false,
      }),
    };

    mockThreatIntel = {
      queryDomains: jest.fn().mockResolvedValue([]),
    };

    mockReport = {
      generateReport: jest.fn().mockReturnValue(mockReportOutput),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AnalysisProcessor,
        StructuredLogger,
        { provide: getRepositoryToken(AnalysisJob), useValue: mockRepository },
        { provide: DownloaderService, useValue: mockDownloader },
        { provide: PreprocessorService, useValue: { preprocess: jest.fn().mockResolvedValue({ files: [], manifest: { name: 'T', version: '1', manifestVersion: 2, apiPermissions: [], hostPermissions: [], contentScripts: [], backgroundScripts: [], rawManifest: {} }, crxHash: 'abc', extractPath: '/tmp', obfuscatedFileCount: 0, hasObfuscation: false, remoteCodeViolations: [] }) } },
        { provide: AgentsOrchestratorService, useValue: { runAgentPipeline: jest.fn().mockResolvedValue(null) } },
        { provide: Agent4DynamicService, useValue: { analyze: jest.fn().mockResolvedValue(null) } },
        { provide: StaticAnalysisService, useValue: mockStatic },
        { provide: SandboxOrchestratorService, useValue: mockDynamic },
        { provide: ThreatIntelService, useValue: mockThreatIntel },
        { provide: ReportService, useValue: mockReport },
        {
          provide: ConfigService,
          useValue: {
            get: jest.fn((key: string) => {
              if (key === 'analysis.staticTimeoutMs') return 60000;
              if (key === 'analysis.dynamicTimeoutMs') return 180000;
              return undefined;
            }),
          },
        },
      ],
    }).compile();

    processor = module.get<AnalysisProcessor>(AnalysisProcessor);
  });

  describe('process', () => {
    const mockJob = {
      data: { extensionId: 'ext-test', jobId: 'job-123' },
    } as any;

    it('should execute full pipeline successfully', async () => {
      await processor.process(mockJob);

      expect(mockDownloader.downloadAndExtract).toHaveBeenCalledWith('ext-test', 'job-123');
      expect(mockStatic.analyze).toHaveBeenCalled();
      expect(mockDynamic.executeDynamicAnalysis).toHaveBeenCalled();
      expect(mockThreatIntel.queryDomains).toHaveBeenCalled();
      expect(mockReport.generateReport).toHaveBeenCalled();
      expect(mockDownloader.cleanup).toHaveBeenCalledWith('ext-test');
    });

    it('should update job status through pipeline stages', async () => {
      await processor.process(mockJob);

      const statusCalls = mockRepository.update.mock.calls.map(
        (c: any[]) => c[1].status,
      );
      expect(statusCalls).toContain(AnalysisStatus.DOWNLOADING);
      expect(statusCalls).toContain(AnalysisStatus.STATIC_ANALYSIS);
      expect(statusCalls).toContain(AnalysisStatus.DYNAMIC_ANALYSIS);
      expect(statusCalls).toContain(AnalysisStatus.THREAT_INTEL);
      expect(statusCalls).toContain(AnalysisStatus.GENERATING_REPORT);
    });

    it('should still run dynamic analysis even with critical static findings', async () => {
      mockStatic.analyze.mockResolvedValue({
        ...mockStaticResult,
        findings: [{
          category: 'data_theft',
          pattern: 'password',
          severity: RiskLevel.CRITICAL,
          location: { file: 'bg.js', line: 1, column: 0 },
          description: 'test',
        }],
        discoveredDomains: [{
          domain: 'bank.com',
          source: 'code',
          context: 'bank',
          platformLevel: 3,
          category: 'banking',
        }],
      });

      await processor.process(mockJob);

      // Dynamic analysis always runs regardless of static verdict — more evidence = better accuracy
      expect(mockDynamic.executeDynamicAnalysis).toHaveBeenCalled();
      expect(mockReport.generateReport).toHaveBeenCalled();
    });

    it('should handle dynamic analysis failure gracefully', async () => {
      mockDynamic.executeDynamicAnalysis.mockRejectedValue(
        new Error('Playwright not available'),
      );

      await processor.process(mockJob);

      expect(mockReport.generateReport).toHaveBeenCalled();
      expect(mockDownloader.cleanup).toHaveBeenCalled();
    });

    it('should handle threat intel failure gracefully', async () => {
      mockThreatIntel.queryDomains.mockRejectedValue(
        new Error('API unreachable'),
      );

      await processor.process(mockJob);

      expect(mockReport.generateReport).toHaveBeenCalled();
    });

    it('should mark job as FAILED and cleanup on download error', async () => {
      mockDownloader.downloadAndExtract.mockRejectedValue(
        new Error('Download failed'),
      );

      await expect(processor.process(mockJob)).rejects.toThrow('Download failed');

      expect(mockRepository.update).toHaveBeenCalledWith('job-123', {
        status: AnalysisStatus.FAILED,
        errorMessage: 'Download failed',
      });
      expect(mockDownloader.cleanup).toHaveBeenCalledWith('ext-test');
    });
  });
});
