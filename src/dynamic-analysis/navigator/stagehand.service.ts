import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Stagehand, AISdkClient } from '@browserbasehq/stagehand';
import { createOpenAICompatible } from '@ai-sdk/openai-compatible';
import { z } from 'zod';
import * as fs from 'fs';
import * as path from 'path';
import { StructuredLogger } from '../../common/logger/logger.service.js';
import type { DomainCategory } from '../../agents/interfaces/agents.interfaces.js';
import type {
  AgentStep,
  SandboxDomainObservation,
} from '../../common/interfaces/analysis.interfaces.js';

@Injectable()
export class StagehandService {
  private readonly modeloOllama: string;
  private readonly ollamaHost: string;
  private readonly storageStatePath: string | undefined;

  constructor(
    config: ConfigService,
    private readonly logger: StructuredLogger,
  ) {
    this.modeloOllama = config.get<string>('MODELO_OLLAMA') ?? 'qwen3:4b';
    this.ollamaHost = (
      config.get<string>('OLLAMA_HOST') ?? 'http://host.docker.internal:11434'
    ).replace(/\/$/, '');
    this.storageStatePath = config.get<string>('demo.storageStatePath');
  }

  async navigateDomain(
    page: any,
    browserContext: any,
    domain: string,
    category: DomainCategory,
    proposito: string,
    extensionPath: string,
    jobId: string,
  ): Promise<SandboxDomainObservation> {
    const tag = `Stagehand|${domain}`;
    this.logger.logWithJob(
      jobId,
      'info',
      `[${tag}] starting (category=${category})`,
      'StagehandService',
    );

    const url = `https://${domain}`;
    const observations: string[] = [];
    const actionsPerformed: string[] = [];
    const agentSteps: AgentStep[] = [];
    let stepCounter = 0;

    const honeypotSessionUsed = await this.injectHoneypotSession(
      browserContext,
      page,
      domain,
      jobId,
    );
    if (honeypotSessionUsed) {
      this.logger.logWithJob(
        jobId,
        'info',
        `[${tag}] honeypot session injected (cookies + localStorage)`,
        'StagehandService',
      );
    }

    let stagehand: Stagehand | undefined;
    try {
      const stagehandOpts = this.buildStagehandOptions(extensionPath);
      stagehand = new Stagehand(stagehandOpts);
      await stagehand.init();
      const page = (stagehand as any).page;

      await page
        .goto(url, { waitUntil: 'domcontentloaded', timeout: 20_000 })
        .catch(() => {});

      if (honeypotSessionUsed) {
        await this.restoreLocalStorage(page, domain, jobId);
      }

      // ── observe ────────────────────────────────────────────────────────
      const observePrompt =
        `Identifica elementos de login, formularios sensibles o campos de datos personales en ${domain} ` +
        `relacionados con el propósito declarado: "${proposito}"`;
      stepCounter++;
      this.logger.logWithJob(
        jobId,
        'info',
        `[${tag}|paso ${stepCounter}] observe → "${observePrompt.slice(0, 100)}…"`,
        'StagehandService',
      );
      const actions = await stagehand
        .observe(observePrompt, { page })
        .catch((e) => {
          this.logger.logWithJob(
            jobId,
            'error',
            `[Stagehand] Error en observe: ${e.message || String(e)}`,
            'StagehandService',
          );
          observations.push(`Error en observe: ${e.message || String(e)}`);
          return [];
        });

      const observeSummary =
        actions.length > 0
          ? actions
              .map((a: any) => `- ${a.description} (selector: ${a.selector})`)
              .join('\n')
          : 'sin elementos relevantes';

      this.logger.logWithJob(
        jobId,
        'info',
        `[${tag}|paso ${stepCounter}] observe ← ${actions.length} elemento(s): ${observeSummary}`,
        'StagehandService',
      );

      agentSteps.push({
        step: stepCounter,
        action: 'observe',
        target: observePrompt.slice(0, 80),
        reasoning: `Stagehand identifica elementos relevantes para "${proposito}"`,
        result: actions.length > 0 ? 'success' : 'no-op',
        timestamp: Date.now(),
        observation: observeSummary,
      });

      const isSensitive =
        category === 'sensible_financiero' ||
        category === 'sensible_identidad' ||
        category === 'sensible_llm';

      // ── act ────────────────────────────────────────────────────────────
      if (isSensitive) {
        stepCounter = await this.runAct(
          stagehand,
          page,
          stepCounter,
          tag,
          jobId,
          actionsPerformed,
          agentSteps,
          'Busca el campo de correo electrónico o nombre de usuario y escribe "test_extwarden@mailtest.com"',
          'type:honeypot_email',
          'Probar si el formulario captura credenciales del honeypot',
        );

        if (actionsPerformed.includes('type:honeypot_email')) {
          stepCounter = await this.runAct(
            stagehand,
            page,
            stepCounter,
            tag,
            jobId,
            actionsPerformed,
            agentSteps,
            'Busca el campo de contraseña y escribe "ExTw4rd3n_F4ke!"',
            'type:honeypot_password',
            'Completar el segundo factor del formulario para forzar submit',
          );

          if (actionsPerformed.includes('type:honeypot_password')) {
            stepCounter = await this.runAct(
              stagehand,
              page,
              stepCounter,
              tag,
              jobId,
              actionsPerformed,
              agentSteps,
              'Haz clic en el botón de Iniciar Sesión, Login o Continuar',
              'click:submit',
              'Disparar el submit para observar si la extensión intercepta',
            );
          }
        }
      } else {
        stepCounter = await this.runAct(
          stagehand,
          page,
          stepCounter,
          tag,
          jobId,
          actionsPerformed,
          agentSteps,
          'Explora la página principal buscando secciones de configuración, perfil de usuario o paneles de control.',
          'act:exploration',
          'Estimular interacción genérica para que la extensión actúe',
        );
      }

      // ── extract ────────────────────────────────────────────────────────
      const ExtensionImpactSchema = z.object({
        detectado: z.boolean(),
        descripcion: z.string(),
      });
      const extractPrompt =
        '¿La extensión del navegador inyectó algún elemento visual, modificó formularios, o alteró el comportamiento de la página?';
      stepCounter++;
      this.logger.logWithJob(
        jobId,
        'info',
        `[${tag}|paso ${stepCounter}] extract → "${extractPrompt.slice(0, 100)}…"`,
        'StagehandService',
      );

      let finalSummary = { detectado: false, descripcion: '' };
      try {
        finalSummary = await stagehand.extract(
          extractPrompt,
          z.object({
            detectado: z.boolean(),
            descripcion: z.string(),
          }),
          { page },
        );

        this.logger.logWithJob(
          jobId,
          'info',
          `[${tag}|paso ${stepCounter}] extract ← detectado=${finalSummary.detectado} desc="${finalSummary.descripcion}"`,
          'StagehandService',
        );
        agentSteps.push({
          step: stepCounter,
          observation: finalSummary.descripcion || 'sin impacto visible',
          action: 'extract',
          target: extractPrompt.slice(0, 80),
          reasoning:
            'Resumir el impacto visible de la extensión sobre la página',
          result: finalSummary.detectado ? 'success' : 'no-op',
          timestamp: Date.now(),
        });
      } catch (e) {
        this.logger.error(
          `[Stagehand] Error en extract: ${e instanceof Error ? e.message : String(e)}`,
          'StagehandService',
        );
        this.logger.logWithJob(
          jobId,
          'error',
          `[Stagehand] Error en extract: ${e instanceof Error ? e.message : String(e)}`,
          'StagehandService',
        );
        agentSteps.push({
          step: stepCounter,
          observation: 'error en extracción',
          action: 'extract',
          target: extractPrompt.slice(0, 80),
          reasoning:
            'Resumir el impacto visible de la extensión sobre la página',
          result: 'failed',
          timestamp: Date.now(),
        });
      }

      if (finalSummary.detectado) {
        observations.push(
          `Comportamiento detectado: ${finalSummary.descripcion}`,
        );
      }

      this.logger.logWithJob(
        jobId,
        'info',
        `[${tag}] finished: ${actionsPerformed.length} actions, ${observations.length} observations`,
        'StagehandService',
      );

      return {
        domain,
        url,
        navigatorUsed: 'stagehand',
        observations,
        actionsPerformed,
        agentSteps,
        requestsToThisDomain: 0,
        domModificationsDetected: !!finalSummary.detectado,
        credentialsSubmitted:
          isSensitive && actionsPerformed.includes('click:submit'),
        honeypotSessionUsed,
      };
    } catch (err) {
      const msg = `Stagehand failed for ${domain}: ${err instanceof Error ? err.message : String(err)}`;
      this.logger.logWithJob(
        jobId,
        'warn',
        `[${tag}] ${msg}`,
        'StagehandService',
      );
      return {
        domain,
        url,
        navigatorUsed: 'stagehand',
        observations: [msg],
        actionsPerformed: [],
        agentSteps,
        requestsToThisDomain: 0,
        domModificationsDetected: false,
        credentialsSubmitted: false,
        honeypotSessionUsed,
        error: msg,
      };
    } finally {
      await stagehand?.close().catch(() => {});
    }
  }

  /**
   * Wrapper around stagehand.act() that logs the prompt, the outcome and
   * registers the step into agentSteps. Mutates actionsPerformed when the
   * action succeeds. Returns the next step counter.
   */
  private async runAct(
    stagehand: Stagehand,
    page: any,
    stepCounter: number,
    tag: string,
    jobId: string,
    actionsPerformed: string[],
    agentSteps: AgentStep[],
    prompt: string,
    actionLabel: string,
    reasoning: string,
  ): Promise<number> {
    const next = stepCounter + 1;
    this.logger.logWithJob(
      jobId,
      'info',
      `[${tag}|paso ${next}] act → "${prompt.slice(0, 100)}…" | razón: ${reasoning}`,
      'StagehandService',
    );
    const res = await stagehand
      .act(prompt, { page })
      .catch(() => ({ success: false }));
    const success = (res as { success?: boolean }).success === true;
    this.logger.logWithJob(
      jobId,
      'info',
      `[${tag}|paso ${next}] act ← ${success ? 'success' : 'failed'} | ${actionLabel}`,
      'StagehandService',
    );
    if (success) actionsPerformed.push(actionLabel);
    agentSteps.push({
      step: next,
      observation: success
        ? `acción ejecutada: ${actionLabel}`
        : 'acción no ejecutada',
      action: 'act',
      target: prompt.slice(0, 80),
      reasoning,
      result: success ? 'success' : 'failed',
      timestamp: Date.now(),
    });
    return next;
  }

  // ─── Honeypot session helpers ─────────────────────────────────────────────

  /**
   * Loads cookies from data/honeypot/states/<domain>.json (or its bare-domain
   * variant) and injects them into the browser context so the extension
   * observes a logged-in session. Returns true if a session was loaded.
   *
   * Stores localStorage origins on the page object for restore after navigation.
   */
  private async injectHoneypotSession(
    browserContext: any,
    page: any,
    domain: string,
    jobId: string,
  ): Promise<boolean> {
    const statePath = this.findStateFile(domain);
    if (!statePath) return false;

    let raw: string;
    try {
      raw = fs.readFileSync(statePath, 'utf-8');
    } catch (err) {
      this.logger.logWithJob(
        jobId,
        'warn',
        `Stagehand — could not read storageState ${statePath}: ${err instanceof Error ? err.message : String(err)}`,
        'StagehandService',
      );
      return false;
    }

    let state: { cookies?: any[]; origins?: any[] };
    try {
      state = JSON.parse(raw);
    } catch {
      return false;
    }

    if (Array.isArray(state.cookies) && state.cookies.length > 0) {
      try {
        await browserContext.addCookies(state.cookies);
      } catch (err) {
        this.logger.logWithJob(
          jobId,
          'warn',
          `Stagehand — addCookies failed for ${domain}: ${err instanceof Error ? err.message : String(err)}`,
          'StagehandService',
        );
        return false;
      }
    }

    // Stash for post-navigation restore
    if (Array.isArray(state.origins)) {
      page.__honeypotOrigins = state.origins;
    }

    this.logger.logWithJob(
      jobId,
      'info',
      `Stagehand — injected honeypot session for ${domain} from ${path.basename(statePath)}`,
      'StagehandService',
    );
    return true;
  }

  private async restoreLocalStorage(
    page: any,
    domain: string,
    jobId: string,
  ): Promise<void> {
    const origins = page.__honeypotOrigins as Array<{
      origin: string;
      localStorage?: Array<{ name: string; value: string }>;
    }>;
    if (!Array.isArray(origins)) return;

    for (const o of origins) {
      const items = o.localStorage ?? [];
      for (const item of items) {
        try {
          await page.evaluate(
            ([k, v]: [string, string]) => localStorage.setItem(k, v),
            [item.name, item.value],
          );
        } catch {
          /* page may have navigated cross-origin */
        }
      }
    }

    this.logger.logWithJob(
      jobId,
      'info',
      `Stagehand — restored localStorage for ${domain}`,
      'StagehandService',
    );
  }

  private findStateFile(domain: string): string | undefined {
    const candidates = [
      this.storageStatePath,
      './data/honeypot/states',
      '/data/honeypot/states',
    ].filter((p): p is string => !!p);

    const bare = domain.replace(/^www\./, '');
    const variants = [domain, bare];
    for (const base of candidates) {
      for (const d of variants) {
        const p = path.join(base, `${d}.json`);
        if (fs.existsSync(p)) return p;
      }
    }
    return undefined;
  }

  private buildStagehandOptions(
    extensionPath?: string,
  ): ConstructorParameters<typeof Stagehand>[0] {
    const base = {
      env: 'LOCAL' as const,
      verbose: 0 as const,
      localBrowserLaunchOptions: {
        headless: true,
        args: extensionPath
          ? [
              `--disable-extensions-except=${extensionPath}`,
              `--load-extension=${extensionPath}`,
            ]
          : [],
      },
      disablePino: true,
    };

    const ollamaProvider = createOpenAICompatible({
      name: 'ollama',
      baseURL: `${this.ollamaHost}/v1`,
      fetch: (url: string, options: RequestInit) => {
        return fetch(url, {
          ...options,
          signal: AbortSignal.timeout(1_200_000),
        });
      },
    });
    const llmClient = new AISdkClient({
      model: ollamaProvider.chatModel(this.modeloOllama),
    });
    return { ...base, llmClient };
  }
}
