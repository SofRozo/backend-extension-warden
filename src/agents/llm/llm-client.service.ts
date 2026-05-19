import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import axios from 'axios';
import { StructuredLogger } from '../../common/logger/logger.service.js';

@Injectable()
export class LlmClientService {
  private readonly modeloOllama: string;
  private readonly ollamaHost: string;
  private readonly timeoutMs: number;

  constructor(
    config: ConfigService,
    private readonly logger: StructuredLogger,
  ) {
    this.modeloOllama = config.get<string>('MODELO_OLLAMA') ?? 'qwen3:8b';
    this.ollamaHost = (
      config.get<string>('OLLAMA_HOST') ?? 'http://host.docker.internal:11434'
    ).replace(/\/$/, '');
    // Axios timeout is AGENT_TIMEOUT_MS + 90s so the job-level withTimeout()
    // always fires first and handles the error gracefully (user-visible warn log)
    // instead of an axios-level cancellation that bypasses the wrapper.
    // Number() is required: ConfigService returns env vars as strings at runtime
    // even when typed as <number>, so without it "420000" + 90000 = "42000090000".
    this.timeoutMs =
      Number(config.get<number>('AGENT_TIMEOUT_MS') ?? 1_200_000) + 90_000;
  }

  isConfigured(): boolean {
    return true;
  }

  async callLLM(
    messages: { system: string; user: string },
    jobId?: string,
    format: 'json' | 'text' = 'json',
  ): Promise<unknown> {
    const start = Date.now();
    try {
      const result = await this.callOllama(messages, format);
      this.logger.logWithJob(
        jobId ?? '-',
        'debug',
        `LLM call completed in ${Date.now() - start}ms (${this.modeloOllama})`,
        'LlmClientService',
      );
      return result;
    } catch (err) {
      this.logger.logWithJob(
        jobId ?? '-',
        'error',
        `LLM call failed after ${Date.now() - start}ms: ${err instanceof Error ? err.message : String(err)}`,
        'LlmClientService',
      );
      throw err;
    }
  }

  private async callOllama(
    messages: { system: string; user: string },
    format: 'json' | 'text',
  ): Promise<unknown> {
    const response = await axios.post(
      `${this.ollamaHost}/api/chat`,
      {
        model: this.modeloOllama,
        messages: [
          { role: 'system', content: messages.system },
          { role: 'user', content: messages.user },
        ],
        stream: false,
        think: false,
        ...(format === 'json' ? { format: 'json' } : {}),
        options: {
          num_ctx: 12288,
          temperature: 0,
          num_predict: format === 'text' ? 1200 : 1024,
        },
      },
      { timeout: this.timeoutMs },
    );
    const ollamaData = response.data as {
      message?: { content?: string };
    };
    const raw = ollamaData.message?.content;
    const stripped = this.stripThinkBlocks(raw ?? '');
    if (format === 'text') {
      if (!stripped) throw new Error('LLM returned an empty response');
      return stripped;
    }
    return this.parseJsonResponse(stripped || raw);
  }

  private stripThinkBlocks(raw: string): string {
    return raw
      .replace(/<think>[\s\S]*?<\/think>/g, '')
      .replace(/<think>[\s\S]*/g, '')
      .replace(/^\?+\.?\s*/, '')
      .trim();
  }

  private parseJsonResponse(raw: string | undefined): unknown {
    if (!raw) throw new Error('LLM returned an empty response');

    const cleaned = raw
      .trim()
      .replace(/^```json\s*/i, '')
      .replace(/^```\s*/i, '')
      .replace(/\s*```$/i, '')
      .trim();

    try {
      return JSON.parse(cleaned);
    } catch {
      const jsonMatch = cleaned.match(/\{[\s\S]*\}|\[[\s\S]*\]/);
      if (jsonMatch) {
        try {
          return JSON.parse(jsonMatch[0]);
        } catch {
          /* fall through */
        }
      }
      throw new Error(
        `LLM returned a response that could not be parsed as JSON: "${cleaned.slice(0, 300)}"`,
      );
    }
  }
}
