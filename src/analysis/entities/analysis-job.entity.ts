import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
} from 'typeorm';
import {
  AnalysisStatus,
  RiskLevel,
} from '../../common/enums/risk-level.enum.js';

@Entity('analysis_jobs')
export class AnalysisJob {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ name: 'extension_id' })
  extensionId: string;

  @Column({ name: 'extension_name', nullable: true })
  extensionName: string;

  @Column({ name: 'extension_version', nullable: true })
  extensionVersion: string;

  @Column({
    type: 'enum',
    enum: AnalysisStatus,
    default: AnalysisStatus.QUEUED,
  })
  status: AnalysisStatus;

  @Column({ name: 'crx_hash', nullable: true })
  crxHash: string;

  @Column({
    name: 'overall_risk',
    type: 'enum',
    enum: RiskLevel,
    nullable: true,
  })
  overallRisk: RiskLevel;

  @Column({ type: 'jsonb', nullable: true })
  report: Record<string, unknown>;

  @Column({ name: 'error_message', nullable: true })
  errorMessage: string;

  @Column({ type: 'float', nullable: true })
  confidence: number;

  @Column({ name: 'analysis_duration_ms', nullable: true })
  analysisDurationMs: number;

  @CreateDateColumn({ name: 'created_at' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at' })
  updatedAt: Date;
}
