import { Test, TestingModule } from '@nestjs/testing';
import { NotFoundException, BadRequestException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { AnalysisController } from '../analysis.controller.js';
import { AnalysisService } from '../analysis.service.js';

describe('AnalysisController', () => {
  let controller: AnalysisController;
  let mockService: any;

  beforeEach(async () => {
    mockService = {
      createAnalysisJob: jest.fn(),
      getJobStatus: jest.fn(),
      getJobWithReport: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [AnalysisController],
      providers: [
        { provide: AnalysisService, useValue: mockService },
        { provide: ConfigService, useValue: { get: jest.fn(() => undefined) } },
      ],
    }).compile();

    controller = module.get<AnalysisController>(AnalysisController);
  });

  describe('POST /analyze', () => {
    it('should create an analysis job and return 202', async () => {
      mockService.createAnalysisJob.mockResolvedValue({
        id: 'uuid-123',
        status: 'queued',
      });

      const result = await controller.analyze({ extensionId: 'ext-abc' });

      expect(result.jobId).toBe('uuid-123');
      expect(result.status).toBe('queued');
      expect(result.message).toContain('queued successfully');
      expect(mockService.createAnalysisJob).toHaveBeenCalledWith(
        'ext-abc',
        false,
      );
    });
  });

  describe('GET /status/:jobId', () => {
    const validUuid = '12345678-1234-1234-1234-123456789abc';

    it('should return job status for valid UUID', async () => {
      mockService.getJobStatus.mockResolvedValue({
        id: validUuid,
        extensionId: 'ext-1',
        extensionName: 'Test Extension',
        status: 'completed',
        overallRisk: 'HIGH',
        createdAt: new Date(),
        updatedAt: new Date(),
      });

      const result = await controller.getStatus(validUuid);
      expect(result.jobId).toBe(validUuid);
      expect(result.status).toBe('completed');
    });

    it('should throw BadRequestException for invalid UUID', async () => {
      await expect(controller.getStatus('not-a-uuid')).rejects.toThrow(
        BadRequestException,
      );
    });

    it('should throw NotFoundException when job not found', async () => {
      mockService.getJobStatus.mockResolvedValue(null);
      await expect(controller.getStatus(validUuid)).rejects.toThrow(
        NotFoundException,
      );
    });
  });

  describe('GET /report/:jobId', () => {
    const validUuid = '12345678-1234-1234-1234-123456789abc';

    it('should return report when analysis is completed', async () => {
      const mockReport = { overallRisk: 'CRITICAL', privacyLabels: [] };
      mockService.getJobWithReport.mockResolvedValue({
        id: validUuid,
        status: 'completed',
        report: mockReport,
      });

      const result = await controller.getReport(validUuid);
      expect(result).toEqual(mockReport);
    });

    it('should return pending message when not completed', async () => {
      mockService.getJobWithReport.mockResolvedValue({
        id: validUuid,
        status: 'static_analysis',
      });

      const result = await controller.getReport(validUuid);
      expect(result.status).toBe('static_analysis');
      expect(result.message).toContain('not yet complete');
    });

    it('should throw BadRequestException for invalid UUID', async () => {
      await expect(controller.getReport('invalid')).rejects.toThrow(
        BadRequestException,
      );
    });

    it('should throw NotFoundException when job not found', async () => {
      mockService.getJobWithReport.mockResolvedValue(null);
      await expect(controller.getReport(validUuid)).rejects.toThrow(
        NotFoundException,
      );
    });
  });
});
