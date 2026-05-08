import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { RetentionService } from '../retention.service.js';
import { AnalysisJob } from '../../analysis/entities/analysis-job.entity.js';
import { StructuredLogger } from '../../common/logger/logger.service.js';

describe('RetentionService', () => {
  let service: RetentionService;
  let mockQueryBuilder: any;
  let mockRepository: any;

  beforeEach(async () => {
    mockQueryBuilder = {
      update: jest.fn().mockReturnThis(),
      set: jest.fn().mockReturnThis(),
      where: jest.fn().mockReturnThis(),
      andWhere: jest.fn().mockReturnThis(),
      execute: jest.fn().mockResolvedValue({ affected: 0 }),
    };

    mockRepository = {
      createQueryBuilder: jest.fn().mockReturnValue(mockQueryBuilder),
      query: jest.fn().mockResolvedValue(undefined),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        RetentionService,
        StructuredLogger,
        {
          provide: getRepositoryToken(AnalysisJob),
          useValue: mockRepository,
        },
      ],
    }).compile();

    service = module.get<RetentionService>(RetentionService);
  });

  describe('purgeExpiredReports', () => {
    it('should execute purge query with 12-month cutoff', async () => {
      mockQueryBuilder.execute.mockResolvedValue({ affected: 3 });

      await service.purgeExpiredReports();

      expect(mockRepository.createQueryBuilder).toHaveBeenCalled();
      expect(mockQueryBuilder.update).toHaveBeenCalledWith(AnalysisJob);
      expect(mockQueryBuilder.set).toHaveBeenCalledWith({
        report: expect.any(Function),
      });
      expect(mockQueryBuilder.where).toHaveBeenCalledWith(
        'created_at < :cutoff',
        expect.objectContaining({ cutoff: expect.any(Date) }),
      );
      expect(mockQueryBuilder.andWhere).toHaveBeenCalledWith(
        'report IS NOT NULL',
      );
    });

    it('should not throw when no reports to purge', async () => {
      mockQueryBuilder.execute.mockResolvedValue({ affected: 0 });
      await expect(service.purgeExpiredReports()).resolves.not.toThrow();
    });

    it('should handle database errors gracefully', async () => {
      mockQueryBuilder.execute.mockRejectedValue(
        new Error('DB connection lost'),
      );
      await expect(service.purgeExpiredReports()).resolves.not.toThrow();
    });
  });

  describe('purgeThreatIntelCache', () => {
    it('should execute DELETE query for expired entries', async () => {
      await service.purgeThreatIntelCache();
      expect(mockRepository.query).toHaveBeenCalledWith(
        'DELETE FROM threat_intel_cache WHERE expires_at < NOW()',
      );
    });

    it('should handle errors gracefully', async () => {
      mockRepository.query.mockRejectedValue(new Error('Table not found'));
      await expect(service.purgeThreatIntelCache()).resolves.not.toThrow();
    });
  });
});
