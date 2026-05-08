import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Cron, CronExpression } from '@nestjs/schedule';
import { AnalysisJob } from '../analysis/entities/analysis-job.entity.js';
import { StructuredLogger } from '../common/logger/logger.service.js';

/**
 * §11 — Data Retention Policy:
 * - Reports retained max 12 months, then purged (report field set to NULL)
 * - CRX hashes retained indefinitely for re-analysis comparison
 * - Network traffic never persisted (analyzed in-memory only)
 */
@Injectable()
export class RetentionService {
  constructor(
    @InjectRepository(AnalysisJob)
    private readonly jobRepository: Repository<AnalysisJob>,
    private readonly logger: StructuredLogger,
  ) {}

  /**
   * Runs daily at 3:00 AM — purge reports older than 12 months.
   * Keeps crx_hash for indefinite re-analysis (§11).
   */
  @Cron(CronExpression.EVERY_DAY_AT_3AM)
  async purgeExpiredReports(): Promise<void> {
    const twelveMonthsAgo = new Date();
    twelveMonthsAgo.setMonth(twelveMonthsAgo.getMonth() - 12);

    try {
      const result = await this.jobRepository
        .createQueryBuilder()
        .update(AnalysisJob)
        .set({ report: () => 'NULL' })
        .where('created_at < :cutoff', { cutoff: twelveMonthsAgo })
        .andWhere('report IS NOT NULL')
        .execute();

      if (result.affected && result.affected > 0) {
        this.logger.log(
          `§11 retention: purged ${result.affected} expired report(s) older than 12 months`,
          'RetentionService',
        );
      }
    } catch (err) {
      this.logger.error(
        `Retention purge failed: ${err instanceof Error ? err.message : String(err)}`,
        undefined,
        'RetentionService',
      );
    }
  }

  /**
   * Runs weekly — purge expired threat intel cache entries.
   */
  @Cron(CronExpression.EVERY_WEEK)
  async purgeThreatIntelCache(): Promise<void> {
    try {
      await this.jobRepository.query(
        `DELETE FROM threat_intel_cache WHERE expires_at < NOW()`,
      );
      this.logger.log(
        'Purged expired threat intel cache entries',
        'RetentionService',
      );
    } catch (err) {
      this.logger.warn(
        `Threat intel cache purge failed: ${err instanceof Error ? err.message : String(err)}`,
        'RetentionService',
      );
    }
  }
}
