import {
  Controller,
  Post,
  Get,
  Body,
  Param,
  HttpCode,
  HttpStatus,
  NotFoundException,
  BadRequestException,
} from '@nestjs/common';
import { AnalysisService } from './analysis.service.js';
import { AnalyzeRequestDto } from './dto/analyze-request.dto.js';
import { AnalysisStatus } from '../common/enums/risk-level.enum.js';

/** RF01: Porcentaje de progreso por estado — permite a clientes mostrar barra de progreso */
const STATUS_PROGRESS: Record<AnalysisStatus, number> = {
  [AnalysisStatus.QUEUED]: 5,
  [AnalysisStatus.DOWNLOADING]: 15,
  [AnalysisStatus.PREPROCESSING]: 25,
  [AnalysisStatus.AI_ANALYSIS]: 38,
  [AnalysisStatus.STATIC_ANALYSIS]: 50,
  [AnalysisStatus.DYNAMIC_ANALYSIS]: 70,
  [AnalysisStatus.THREAT_INTEL]: 85,
  [AnalysisStatus.GENERATING_REPORT]: 92,
  [AnalysisStatus.COMPLETED]: 100,
  [AnalysisStatus.FAILED]: 0,
};

@Controller()
export class AnalysisController {
  constructor(private readonly analysisService: AnalysisService) {}

  @Post('analyze')
  @HttpCode(HttpStatus.ACCEPTED)
  async analyze(@Body() dto: AnalyzeRequestDto) {
    const job = await this.analysisService.createAnalysisJob(
      dto.extensionId,
      dto.demo === true,
      dto.navigator,
    );
    return {
      jobId: job.id,
      status: job.status,
      queue: dto.demo === true ? 'analysis-demo' : 'analysis',
      navigator: dto.navigator ?? 'default (env)',
      message: 'Analysis job queued successfully',
    };
  }

  @Get('status/:jobId')
  async getStatus(@Param('jobId') jobId: string) {
    if (
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(
        jobId,
      )
    ) {
      throw new BadRequestException('Invalid job ID format');
    }

    const job = await this.analysisService.getJobStatus(jobId);
    if (!job) {
      throw new NotFoundException(`Job ${jobId} not found`);
    }

    return {
      jobId: job.id,
      extensionId: job.extensionId,
      extensionName: job.extensionName,
      status: job.status,
      progress: STATUS_PROGRESS[job.status] ?? 0,
      overallRisk: job.overallRisk,
      createdAt: job.createdAt,
      updatedAt: job.updatedAt,
      /** RF01: Possible status values for client reference */
      possibleStatuses: Object.values(AnalysisStatus),
    };
  }

  @Get('report/:jobId')
  async getReport(@Param('jobId') jobId: string) {
    if (
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(
        jobId,
      )
    ) {
      throw new BadRequestException('Invalid job ID format');
    }

    const job = await this.analysisService.getJobWithReport(jobId);
    if (!job) {
      throw new NotFoundException(`Job ${jobId} not found`);
    }

    if (job.status !== AnalysisStatus.COMPLETED) {
      return {
        jobId: job.id,
        status: job.status,
        message: 'Analysis is not yet complete',
      };
    }

    return job.report;
  }
}
