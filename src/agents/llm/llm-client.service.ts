import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import axios from 'axios';
import { StructuredLogger } from '../../common/logger/logger.service.js';

/**
 * Thin HTTP client that routes LLM calls to either a local Ollama instance
 * or Google Gemini Flash (cloud, free tier).
 *
 * All agents call this service — never the external APIs directly.
 * Controlled by env vars:
 *   USAR_OLLAMA   = "true" (default) | "false"
 *   MODELO_OLLAMA = "qwen3:8b" (default)
 *   OLLAMA_HOST   = "http://localhost:11434" (default)
 *   GOOGLE_API_KEY = required when USAR_OLLAMA=false
 *   AGENT_TIMEOUT_MS = 120000 (default, per-call)
 */
@Injectable()
export class LlmClientService {
  private readonly usarOllama: boolean;
  private readonly modeloOllama: string;
  private readonly ollamaHost: string;
  private readonly googleApiKey: string | undefined;
  private readonly timeoutMs: number;

  constructor(
    private readonly config: ConfigService,
    private readonly logger: StructuredLogger,
  ) {
    this.usarOllama = (config.get<string>('USAR_OLLAMA') ?? 'true') !== 'false';
    this.modeloOllama = config.get<string>('MODELO_OLLAMA') ?? 'qwen3:8b';
    this.ollamaHost = (
      config.get<string>('OLLAMA_HOST') ?? 'http://localhost:11434'
    ).replace(/\/$/, '');
    this.googleApiKey = config.get<string>('GOOGLE_API_KEY');
    this.timeoutMs = config.get<number>('AGENT_TIMEOUT_MS') ?? 120_000;
  }

  /** Returns false when neither Ollama nor Gemini is configured. */
  isConfigured(): boolean {
    return this.usarOllama || !!this.googleApiKey;
  }

  /**
   * Call the configured LLM and return the parsed JSON response.
   * Throws if the LLM is unreachable, times out, or returns non-JSON.
   */
  async callLLM(prompt: string, jobId?: string): Promise<unknown> {
    if (!this.isConfigured()) {
      throw new Error(
        'No LLM configured: set USAR_OLLAMA=true and ensure Ollama is running, ' +
          'or set USAR_OLLAMA=false and provide GOOGLE_API_KEY.',
      );
    }

    const start = Date.now();
    try {
      const result = this.usarOllama
        ? await this.callOllama(prompt)
        : await this.callGemini(prompt);

      this.logger.logWithJob(
        jobId ?? '-',
        'debug',
        `LLM call completed in ${Date.now() - start}ms (${this.usarOllama ? this.modeloOllama : 'gemini-2.0-flash'})`,
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

  // ─── Ollama ─────────────────────────────────────────────────────────────────

  private async callOllama(prompt: string): Promise<unknown> {
    const response = await axios.post(
      `${this.ollamaHost}/api/generate`,
      {
        model: this.modeloOllama,
        prompt:
          prompt +
          '\n\nResponde SOLO con JSON válido. Sin texto adicional ni bloques de código markdown.',
        stream: false,
        format: 'json',
      },
      { timeout: this.timeoutMs },
    );
    const ollamaData = response.data as { response?: string };
    return this.parseJsonResponse(ollamaData.response);
  }

  // ─── Gemini Flash ────────────────────────────────────────────────────────────

  private async callGemini(prompt: string): Promise<unknown> {
    if (!this.googleApiKey) {
      throw new Error(
        'GOOGLE_API_KEY is not set (required when USAR_OLLAMA=false)',
      );
    }

    const url =
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent` +
      `?key=${this.googleApiKey}`;

    const response = await axios.post(
      url,
      {
        contents: [{ parts: [{ text: prompt }] }],
        generationConfig: { responseMimeType: 'application/json' },
      },
      { timeout: this.timeoutMs },
    );

    const geminiData = response.data as {
      candidates?: Array<{ content?: { parts?: Array<{ text?: string }> } }>;
    };
    const raw = geminiData.candidates?.[0]?.content?.parts?.[0]?.text;
    return this.parseJsonResponse(raw);
  }

  // ─── JSON parsing ────────────────────────────────────────────────────────────

  private parseJsonResponse(raw: string | undefined): unknown {
    if (!raw) throw new Error('LLM returned an empty response');

    // Strip markdown code fences if present
    const cleaned = raw
      .trim()
      .replace(/^```json\s*/i, '')
      .replace(/^```\s*/i, '')
      .replace(/\s*```$/i, '')
      .trim();

    try {
      return JSON.parse(cleaned);
    } catch {
      // Last resort: find the first JSON object or array in the text
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
