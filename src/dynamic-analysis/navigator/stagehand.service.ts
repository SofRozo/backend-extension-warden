import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Stagehand, AISdkClient } from '@browserbasehq/stagehand';
import { createOpenAICompatible } from '@ai-sdk/openai-compatible';
import { z } from 'zod';
import { StructuredLogger } from '../../common/logger/logger.service.js';
import type { DomainCategory } from '../../agents/interfaces/agents.interfaces.js';
import type { SandboxDomainObservation } from '../../common/interfaces/analysis.interfaces.js';

@Injectable()
export class StagehandService {
  private readonly usarOllama: boolean;
  private readonly modeloOllama: string;
  private readonly ollamaHost: string;
  private readonly googleApiKey: string | undefined;

  constructor(
    private readonly config: ConfigService,
    private readonly logger: StructuredLogger,
  ) {
    this.usarOllama = (config.get<string>('USAR_OLLAMA') ?? 'true') !== 'false';
    this.modeloOllama = config.get<string>('MODELO_OLLAMA') ?? 'qwen3.5:9b';
    this.ollamaHost = (
      config.get<string>('OLLAMA_HOST') ?? 'http://host.docker.internal:11434'
    ).replace(/\/$/, '');
    this.googleApiKey = config.get<string>('GOOGLE_API_KEY');
  }

  async navigateDomain(
    page: any,
    domain: string,
    category: DomainCategory,
    proposito: string,
    jobId: string,
  ): Promise<SandboxDomainObservation> {
    this.logger.logWithJob(
      jobId,
      'info',
      `Stagehand — starting analysis of ${domain}`,
      'StagehandService',
    );

    const url = `https://${domain}`;
    const observations: string[] = [];
    const actionsPerformed: string[] = [];

    let stagehand: Stagehand | undefined;
    try {
      const stagehandOpts = this.buildStagehandOptions();
      stagehand = new Stagehand(stagehandOpts);
      // init() bootstraps the LLM client and its own internal browser.
      // We pass { page } to each method to target the sandbox page (extension loaded).
      await stagehand.init();

      await page
        .goto(url, { waitUntil: 'domcontentloaded', timeout: 15_000 })
        .catch(() => { });

      // observe() returns Action[] — potential actions identified on the page
      this.logger.logWithJob(
        jobId,
        'info',
        `Stagehand — observing ${domain}`,
        'StagehandService',
      );
      const actions = await stagehand
        .observe(
          `Identifica elementos de login, formularios sensibles o campos de datos personales en ${domain} ` +
          `relacionados con el propósito declarado: "${proposito}"`,
          { page },
        )
        .catch(() => []);

      if (actions.length > 0) {
        const summary = actions
          .slice(0, 5)
          .map((a) => a.description)
          .join('; ');
        observations.push(`Elementos identificados: ${summary}`);
      }

      const isSensitive =
        category === 'sensible_financiero' || category === 'sensible_identidad';

      if (isSensitive) {
        this.logger.logWithJob(
          jobId,
          'info',
          'Stagehand — testing login form with honeypot credentials',
          'StagehandService',
        );

        const emailAct = await stagehand
          .act(
            'Busca el campo de correo electrónico o nombre de usuario y escribe "test_extwarden@mailtest.com"',
            { page },
          )
          .catch(() => ({ success: false }));

        if (emailAct.success) {
          actionsPerformed.push('type:honeypot_email');

          const passAct = await stagehand
            .act('Busca el campo de contraseña y escribe "ExTw4rd3n_F4ke!"', {
              page,
            })
            .catch(() => ({ success: false }));

          if (passAct.success) {
            actionsPerformed.push('type:honeypot_password');
            await stagehand
              .act(
                'Haz clic en el botón de Iniciar Sesión, Login o Continuar',
                { page },
              )
              .catch(() => { });
            actionsPerformed.push('click:submit');
          }
        }
      } else {
        await stagehand
          .act(
            'Explora la página principal buscando secciones de configuración, perfil de usuario o paneles de control.',
            { page },
          )
          .catch(() => { });
        actionsPerformed.push('act:exploration');
      }

      const ExtensionImpactSchema = z.object({
        detectado: z.boolean(),
        descripcion: z.string(),
      });

      const finalSummary = await stagehand
        .extract(
          '¿La extensión del navegador inyectó algún elemento visual, modificó formularios, o alteró el comportamiento de la página?',
          ExtensionImpactSchema,
          { page },
        )
        .catch(() => ({ detectado: false, descripcion: '' }));

      if (finalSummary.detectado) {
        observations.push(
          `Comportamiento detectado: ${finalSummary.descripcion}`,
        );
      }

      return {
        domain,
        url,
        observations,
        actionsPerformed,
        requestsToThisDomain: 0,
        domModificationsDetected: !!finalSummary.detectado,
        credentialsSubmitted:
          isSensitive && actionsPerformed.includes('click:submit'),
      };
    } catch (err) {
      const msg = `Stagehand failed for ${domain}: ${err instanceof Error ? err.message : String(err)}`;
      this.logger.logWithJob(jobId, 'warn', msg, 'StagehandService');
      return {
        domain,
        url,
        observations: [msg],
        actionsPerformed: [],
        requestsToThisDomain: 0,
        domModificationsDetected: false,
        credentialsSubmitted: false,
        error: msg,
      };
    } finally {
      await stagehand?.close().catch(() => { });
    }
  }

  private buildStagehandOptions(): ConstructorParameters<typeof Stagehand>[0] {
    const base = {
      env: 'LOCAL' as const,
      verbose: 0 as const,
      localBrowserLaunchOptions: { headless: true },
      disablePino: true,
    };

    if (this.usarOllama) {
      // Use @ai-sdk/openai-compatible to talk to Ollama's OpenAI-compatible endpoint.
      // AISdkClient bridges the AI SDK model interface into Stagehand's LLMClient contract.
      const ollamaProvider = createOpenAICompatible({
        name: 'ollama',
        baseURL: `${this.ollamaHost}/v1`,
      });
      const llmClient = new AISdkClient({
        model: ollamaProvider.chatModel(this.modeloOllama),
      });
      return { ...base, llmClient };
    }

    // Gemini: "gemini-2.0-flash" is a known model string, Stagehand resolves provider via AI SDK.
    return {
      ...base,
      model: 'gemini-2.0-flash',
      apiKey: this.googleApiKey,
    };
  }
}
