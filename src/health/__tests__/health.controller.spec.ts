import { Test, TestingModule } from '@nestjs/testing';
import { ServiceUnavailableException } from '@nestjs/common';
import { getRepositoryToken } from '@nestjs/typeorm';
import { getQueueToken } from '@nestjs/bullmq';
import { HealthController } from '../health.controller.js';
import { AnalysisJob } from '../../analysis/entities/analysis-job.entity.js';

describe('HealthController', () => {
  let controller: HealthController;
  let mockRepository: any;
  let mockQueue: any;

  beforeEach(async () => {
    mockRepository = {
      query: jest.fn(),
    };

    mockQueue = {
      client: Promise.resolve({
        ping: jest.fn().mockResolvedValue('PONG'),
      }),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [HealthController],
      providers: [
        { provide: getRepositoryToken(AnalysisJob), useValue: mockRepository },
        { provide: getQueueToken('analysis'), useValue: mockQueue },
      ],
    }).compile();

    controller = module.get<HealthController>(HealthController);
  });

  describe('GET /health', () => {
    it('should return ok status with uptime and memory', () => {
      const result = controller.check();
      expect(result.status).toBe('ok');
      expect(result.service).toBe('ext-sandbox');
      expect(result.uptime).toBeDefined();
      expect(result.memory).toBeDefined();
      expect(result.timestamp).toBeDefined();
    });
  });

  describe('GET /health/ready', () => {
    it('should return ready when both DB and Redis are up', async () => {
      mockRepository.query.mockResolvedValue([{ '?column?': 1 }]);

      const result = await controller.ready();
      expect(result.status).toBe('ready');
      expect(result.checks.database).toBe('up');
      expect(result.checks.redis).toBe('up');
    });

    it('should throw ServiceUnavailableException when DB is down', async () => {
      mockRepository.query.mockRejectedValue(new Error('Connection refused'));

      await expect(controller.ready()).rejects.toThrow(
        ServiceUnavailableException,
      );
    });

    it('should throw ServiceUnavailableException when Redis is down', async () => {
      mockRepository.query.mockResolvedValue([{ '?column?': 1 }]);
      mockQueue.client = Promise.resolve({
        ping: jest.fn().mockRejectedValue(new Error('Redis down')),
      });

      // Re-create controller with broken Redis
      const module = await Test.createTestingModule({
        controllers: [HealthController],
        providers: [
          {
            provide: getRepositoryToken(AnalysisJob),
            useValue: mockRepository,
          },
          { provide: getQueueToken('analysis'), useValue: mockQueue },
        ],
      }).compile();

      const ctrl = module.get<HealthController>(HealthController);
      await expect(ctrl.ready()).rejects.toThrow(ServiceUnavailableException);
    });
  });
});
