import { Injectable, LoggerService as NestLoggerService } from '@nestjs/common';

@Injectable()
export class StructuredLogger implements NestLoggerService {
  private formatMessage(
    level: string,
    message: string,
    context?: string,
    meta?: Record<string, unknown>,
  ): string {
    const entry = {
      timestamp: new Date().toISOString(),
      level,
      context: context || 'Application',
      message,
      ...meta,
    };
    return JSON.stringify(entry);
  }

  log(message: string, context?: string, meta?: Record<string, unknown>) {
    console.log(this.formatMessage('info', message, context, meta));
  }

  error(
    message: string,
    trace?: string,
    context?: string,
    meta?: Record<string, unknown>,
  ) {
    console.error(
      this.formatMessage('error', message, context, { trace, ...meta }),
    );
  }

  warn(message: string, context?: string, meta?: Record<string, unknown>) {
    console.warn(this.formatMessage('warn', message, context, meta));
  }

  debug(message: string, context?: string, meta?: Record<string, unknown>) {
    console.debug(this.formatMessage('debug', message, context, meta));
  }

  verbose(message: string, context?: string, meta?: Record<string, unknown>) {
    console.log(this.formatMessage('verbose', message, context, meta));
  }

  logWithJob(
    jobId: string,
    level: string,
    message: string,
    context?: string,
    meta?: Record<string, unknown>,
  ) {
    const fullMeta = { jobId, ...meta };
    switch (level) {
      case 'error':
        this.error(message, undefined, context, fullMeta);
        break;
      case 'warn':
        this.warn(message, context, fullMeta);
        break;
      case 'debug':
        this.debug(message, context, fullMeta);
        break;
      default:
        this.log(message, context, fullMeta);
    }
  }
}
