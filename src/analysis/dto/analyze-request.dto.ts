import {
  IsString,
  Matches,
  IsNotEmpty,
  IsBoolean,
  IsOptional,
} from 'class-validator';
import { Transform } from 'class-transformer';

export class AnalyzeRequestDto {
  @IsString()
  @IsNotEmpty()
  @Matches(/^[a-z]{32}$/, {
    message:
      'extensionId must be a valid Chrome Web Store extension ID (32 lowercase letters)',
  })
  extensionId: string;

  /**
   * Route this job to the visual demo queue (`analysis-demo`) instead of the
   * default headless queue (`analysis`). The demo worker (DEMO_MODE=true,
   * WORKER_QUEUE=analysis-demo) only consumes that queue, so background and
   * visual processing run side by side without competing for jobs.
   */
  @IsOptional()
  @IsBoolean()
  @Transform(({ value }: { value: unknown }) =>
    typeof value === 'string' ? value.toLowerCase() === 'true' : Boolean(value),
  )
  demo?: boolean;
}
