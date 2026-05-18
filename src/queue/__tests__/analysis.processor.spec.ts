import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { ConfigService } from '@nestjs/config';
import { AnalysisProcessor } from '../analysis.processor.js';
import { AnalysisJob } from '../../analysis/entities/analysis-job.entity.js';
import { DownloaderService } from '../../downloader/downloader.service.js';
import { PreprocessorService } from '../../preprocessor/preprocessor.service.js';
import { AgentsOrchestratorService } from '../../agents/agents-orchestrator.service.js';
import { StaticAnalysisService } from '../../static-analysis/static-analysis.service.js';
import { ReportService } from '../../report/report.service.js';
import { StructuredLogger } from '../../common/logger/logger.service.js';
import { AnalysisStatus } from '../../common/enums/risk-level.enum.js';

describe('AnalysisProcessor', () => {
  let processor: AnalysisProcessor;
  let mockRepository: any;
  let mockDownloader: any;
  let mockStatic: any;
  let mockPreprocessor: any;
  let mockReport: any;
  let mockAgents: any;

  beforeEach(async () => {
    mockRepository = {
      update: jest.fn().mockResolvedValue({ affected: 1 }),
    };

    mockDownloader = {
      downloadAndExtract: jest.fn().mockResolvedValue({
        crxPath: '/tmp/ext.crx',
        extractPath: '/tmp/extracted/ext',
        crxHash: 'abc123',
      }),
      fetchCwsCategory: jest.fn().mockResolvedValue(null),
      cleanup: jest.fn(),
    };

    mockPreprocessor = {
      preprocess: jest.fn().mockResolvedValue({
        files: [],
        manifest: {
          name: 'T',
          version: '1',
          manifestVersion: 2,
          apiPermissions: [],
          hostPermissions: [],
          contentScripts: [],
          backgroundScripts: [],
          rawManifest: {},
        },
        crxHash: 'abc123',
        extractPath: '/tmp',
        obfuscatedFileCount: 0,
        hasObfuscation: false,
        remoteCodeViolations: [],
        resultado1: [],
        resultado2_priority: [],
        resultado2_unknown: [],
      }),
    };

    mockStatic = {
      analyze: jest.fn().mockResolvedValue(undefined),
    };

    mockReport = {
      buildPreAgentSummary: jest.fn().mockReturnValue({
        resultado1: [],
        domainFindings: [],
        resumenUsuario: [],
      }),
      generateReport: jest.fn().mockReturnValue({
        agente1: null,
        hallazgos_estaticos_positivos: [],
        estructura: {
          resultado1: [],
          resultado2_priority: [],
          resultado2_unknown: [],
        },
      }),
    };

    mockAgents = {
      run: jest.fn().mockResolvedValue({
        agent1: null,
        ranSuccessfully: false,
        errors: [],
      }),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AnalysisProcessor,
        StructuredLogger,
        { provide: getRepositoryToken(AnalysisJob), useValue: mockRepository },
        { provide: DownloaderService, useValue: mockDownloader },
        { provide: PreprocessorService, useValue: mockPreprocessor },
        { provide: AgentsOrchestratorService, useValue: mockAgents },
        { provide: StaticAnalysisService, useValue: mockStatic },
        { provide: ReportService, useValue: mockReport },
        {
          provide: ConfigService,
          useValue: {
            get: jest.fn((key: string) => {
              if (key === 'AGENT_TIMEOUT_MS') return 30000;
              if (key === 'analysis.preprocessTimeoutMs') return 30000;
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

    it('should execute the pipeline successfully', async () => {
      await processor.process(mockJob);

      expect(mockDownloader.downloadAndExtract).toHaveBeenCalledWith(
        'ext-test',
        'job-123',
        undefined,
      );
      expect(mockPreprocessor.preprocess).toHaveBeenCalled();
      expect(mockStatic.analyze).toHaveBeenCalled();
      expect(mockAgents.run).toHaveBeenCalled();
      expect(mockReport.generateReport).toHaveBeenCalled();
      expect(mockDownloader.cleanup).toHaveBeenCalledWith('ext-test');
    });

    it('should advance through pipeline status stages', async () => {
      await processor.process(mockJob);

      const statusCalls = mockRepository.update.mock.calls.map(
        (c: any[]) => c[1].status,
      );
      expect(statusCalls).toContain(AnalysisStatus.DOWNLOADING);
      expect(statusCalls).toContain(AnalysisStatus.PREPROCESSING);
      expect(statusCalls).toContain(AnalysisStatus.AI_ANALYSIS);
      expect(statusCalls).toContain(AnalysisStatus.GENERATING_REPORT);
      expect(statusCalls).toContain(AnalysisStatus.COMPLETED);
    });

    it('should mark job as FAILED and cleanup on download error', async () => {
      mockDownloader.downloadAndExtract.mockRejectedValue(
        new Error('Download failed'),
      );

      await expect(processor.process(mockJob)).rejects.toThrow(
        'Download failed',
      );

      expect(mockRepository.update).toHaveBeenCalledWith('job-123', {
        status: AnalysisStatus.FAILED,
        errorMessage: 'Download failed',
      });
      expect(mockDownloader.cleanup).toHaveBeenCalledWith('ext-test');
    });
  });
});
