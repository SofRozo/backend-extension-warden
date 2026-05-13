import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { InjectQueue } from '@nestjs/bullmq';
import { Queue } from 'bullmq';
import { AnalysisJob } from './entities/analysis-job.entity.js';
import { AnalysisStatus } from '../common/enums/risk-level.enum.js';
import { StructuredLogger } from '../common/logger/logger.service.js';

@Injectable()
export class AnalysisService {
  constructor(
    @InjectRepository(AnalysisJob)
    private readonly jobRepository: Repository<AnalysisJob>,
    @InjectQueue('analysis')
    private readonly analysisQueue: Queue,
    @InjectQueue('analysis-demo')
    private readonly demoQueue: Queue,
    private readonly logger: StructuredLogger,
  ) {}

  async createAnalysisJob(
    extensionId?: string,
    demo: boolean = false,
    navigator?: 'stagehand' | 'intelligent_navigator',
    packagePath?: string,
  ): Promise<AnalysisJob> {
    const sourceId = extensionId ?? `local-${Date.now()}`;
    const job = this.jobRepository.create({
      extensionId: sourceId,
      status: AnalysisStatus.QUEUED,
    });

    const savedJob = await this.jobRepository.save(job);

    const targetQueue = demo ? this.demoQueue : this.analysisQueue;

    await targetQueue.add(
      'analyze-extension',
      {
        extensionId,
        packagePath,
        jobId: savedJob.id,
        demo,
        navigator,
      },
      {
        attempts: 2,
        backoff: {
          type: 'exponential',
          delay: 5000,
        },
        removeOnComplete: { count: 100 },
        removeOnFail: { count: 50 },
        // RNF02: Hard timeout enforced by processor lockDuration
        // and per-stage withTimeout() wrappers in AnalysisProcessor
      },
    );

    this.logger.logWithJob(
      savedJob.id,
      'info',
      `Job created and queued (queue=${targetQueue.name}` +
        (navigator ? `, navigator=${navigator}` : '') +
        `) for extension ${sourceId}`,
      'AnalysisService',
    );

    return savedJob;
  }

  async getJobStatus(jobId: string): Promise<AnalysisJob | null> {
    return this.jobRepository.findOne({ where: { id: jobId } });
  }

  async getJobWithReport(jobId: string): Promise<AnalysisJob | null> {
    return this.jobRepository.findOne({ where: { id: jobId } });
  }
}
