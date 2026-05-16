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
    this.modeloOllama = config.get<string>('MODELO_OLLAMA') ?? 'qwen3:4b';
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
  ): Promise<unknown> {
    const start = Date.now();
    try {
      const result = await this.callOllama(messages);
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

  private async callOllama(messages: {
    system: string;
    user: string;
  }): Promise<unknown> {
    const response = await axios.post(
      `${this.ollamaHost}/api/chat`,
      {
        model: this.modeloOllama,
        messages: [
          { role: 'system', content: messages.system },
          { role: 'user', content: '/no_think\n\n' + messages.user },
        ],
        stream: false,
        format: 'json',
        options: {
          num_ctx: 16384,
          temperature: 0,
          num_predict: 1024,
        },
      },
      { timeout: this.timeoutMs },
    );
    const ollamaData = response.data as {
      message?: { content?: string };
    };
    return this.parseJsonResponse(ollamaData.message?.content);
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
