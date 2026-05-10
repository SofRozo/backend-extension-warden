import {
  IsString,
  Matches,
  IsNotEmpty,
  IsBoolean,
  IsOptional,
  IsIn,
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

  /**
   * Which dynamic-analysis navigator to use for this specific job.
   * - 'stagehand'            → Stagehand (LLM + Playwright agent)
   * - 'intelligent_navigator' → IntelligentNavigator (custom rule-based agent)
   *
   * When omitted, falls back to the server-level default set by the env var
   * ANALYSIS_USE_STAGEHAND (true → stagehand, false → intelligent_navigator).
   *
   * Usage from terminal:
   *   curl -X POST http://localhost:3000/analyze \
   *     -H 'Content-Type: application/json' \
   *     -d '{"extensionId":"...","navigator":"stagehand"}'
   */
  @IsOptional()
  @IsString()
  @IsIn(['stagehand', 'intelligent_navigator'], {
    message: 'navigator must be either "stagehand" or "intelligent_navigator"',
  })
  navigator?: 'stagehand' | 'intelligent_navigator';
}
