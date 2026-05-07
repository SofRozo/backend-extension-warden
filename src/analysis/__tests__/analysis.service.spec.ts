import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { getQueueToken } from '@nestjs/bullmq';
import { AnalysisService } from '../analysis.service.js';
import { AnalysisJob } from '../entities/analysis-job.entity.js';
import { AnalysisStatus } from '../../common/enums/risk-level.enum.js';
import { StructuredLogger } from '../../common/logger/logger.service.js';

describe('AnalysisService', () => {
  let service: AnalysisService;
  let mockRepository: any;
  let mockQueue: any;

  beforeEach(async () => {
    mockRepository = {
      create: jest.fn((data: any) => ({ id: 'uuid-123', ...data })),
      save: jest.fn((entity: any) => Promise.resolve({ ...entity, id: 'uuid-123' })),
      findOne: jest.fn(),
    };

    mockQueue = {
      add: jest.fn().mockResolvedValue({ id: 'bull-job-1' }),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AnalysisService,
        StructuredLogger,
        {
          provide: getRepositoryToken(AnalysisJob),
          useValue: mockRepository,
        },
        {
          provide: getQueueToken('analysis'),
          useValue: mockQueue,
        },
        {
          provide: getQueueToken('analysis-demo'),
          useValue: mockQueue,
        },
      ],
    }).compile();

    service = module.get<AnalysisService>(AnalysisService);
  });

  describe('createAnalysisJob', () => {
    it('should create a job with QUEUED status', async () => {
      const job = await service.createAnalysisJob('ext-abc123');

      expect(mockRepository.create).toHaveBeenCalledWith({
        extensionId: 'ext-abc123',
        status: AnalysisStatus.QUEUED,
      });
      expect(mockRepository.save).toHaveBeenCalled();
    });

    it('should add the job to the analysis queue', async () => {
      await service.createAnalysisJob('ext-abc123');

      expect(mockQueue.add).toHaveBeenCalledWith(
        'analyze-extension',
        expect.objectContaining({
          extensionId: 'ext-abc123',
          jobId: 'uuid-123',
        }),
        expect.objectContaining({
          attempts: 2,
          removeOnComplete: { count: 100 },
        }),
      );
    });

    it('should return the saved job entity', async () => {
      const result = await service.createAnalysisJob('ext-test');
      expect(result).toHaveProperty('id');
      expect(result.extensionId).toBe('ext-test');
    });
  });

  describe('getJobStatus', () => {
    it('should query repository by jobId', async () => {
      mockRepository.findOne.mockResolvedValue({ id: 'j1', status: 'completed' });
      const result = await service.getJobStatus('j1');
      expect(mockRepository.findOne).toHaveBeenCalledWith({
        where: { id: 'j1' },
      });
      expect(result).toBeDefined();
    });

    it('should return null for non-existent job', async () => {
      mockRepository.findOne.mockResolvedValue(null);
      const result = await service.getJobStatus('nonexistent');
      expect(result).toBeNull();
    });
  });

  describe('getJobWithReport', () => {
    it('should return job with report data', async () => {
      const mockJob = {
        id: 'j1',
        status: 'completed',
        report: { overallRisk: 'CRITICAL' },
      };
      mockRepository.findOne.mockResolvedValue(mockJob);
      const result = await service.getJobWithReport('j1');
      expect(result?.report).toBeDefined();
    });
  });
});
