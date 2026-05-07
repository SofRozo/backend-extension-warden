import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
} from 'typeorm';
import { PlatformLevel } from '../../common/enums/risk-level.enum.js';

@Entity('platform_states')
export class PlatformState {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ unique: true })
  domain: string;

  @Column({ name: 'platform_name' })
  platformName: string;

  @Column({
    type: 'enum',
    enum: PlatformLevel,
    default: PlatformLevel.LEVEL_3_RESTRICTED,
  })
  level: PlatformLevel;

  @Column({ name: 'storage_state_path', nullable: true })
  storageStatePath: string;

  @Column({ name: 'last_renewal', type: 'timestamp', nullable: true })
  lastRenewal: Date;

  @Column({ name: 'is_active', default: true })
  isActive: boolean;

  @Column({ nullable: true })
  category: string;

  @Column({ name: 'login_url', nullable: true })
  loginUrl: string;

  @CreateDateColumn({ name: 'created_at' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at' })
  updatedAt: Date;
}
