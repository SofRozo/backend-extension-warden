import { Injectable } from '@nestjs/common';
import * as fs from 'fs';
import * as path from 'path';
import { ConfigService } from '@nestjs/config';
import { LlmClientService } from '../../agents/llm/llm-client.service.js';
import { StructuredLogger } from '../../common/logger/logger.service.js';
import type { DomainCategory } from '../../agents/interfaces/agents.interfaces.js';
import type {
  AgentStep,
  SandboxDomainObservation,
} from '../../common/interfaces/analysis.interfaces.js';

// ─── Constants ────────────────────────────────────────────────────────────────

const FAKE_EMAIL = 'test_extwarden@mailtest.com';
const FAKE_PASSWORD = 'ExTw4rd3n_F4ke!';
const MAX_STEPS_PER_DOMAIN = 5;
const STEP_WAIT_MS = 2500;

// ─── Internal action type ─────────────────────────────────────────────────────

interface NavigatorAction {
  action: 'click' | 'type' | 'navigate' | 'wait' | 'done';
  element_text?: string;
  selector?: string;
  value?: string;
  url?: string;
  observation: string;
  reasoning: string;
}

// ─── Prompt ───────────────────────────────────────────────────────────────────

const NAVIGATOR_SYSTEM_PROMPT =
  `Eres un auditor de seguridad de extensiones de navegador.\n` +
  `Controlas un navegador Playwright para provocar comportamiento malicioso en extensiones instaladas.\n\n` +
  `Decide el siguiente paso para revelar el comportamiento de la extensión.\n` +
  `Prioriza: interactuar con formularios de login, buscar elementos inyectados, navegar a secciones sensibles.\n` +
  `Si ya has interactuado suficientemente o no hay más acciones útiles, usa "done".\n\n` +
  `Responde SOLO con JSON válido:\n` +
  `{\n` +
  `  "action": "click|type|navigate|wait|done",\n` +
  `  "element_text": "texto visible del elemento a interactuar (para click/type)",\n` +
  `  "selector": "selector CSS opcional si lo puedes inferir",\n` +
  `  "value": "texto a escribir (solo para action=type)",\n` +
  `  "url": "URL completa (solo para action=navigate)",\n` +
  `  "observation": "qué observas sobre el comportamiento de la extensión en esta página",\n` +
  `  "reasoning": "por qué esta acción ayuda a detectar comportamiento malicioso"\n` +
  `}`;

const buildPrompt = (
  snapshot: string,
  task: string,
  step: number,
  previousObservations: string[],
): { system: string; user: string } => ({
  system: NAVIGATOR_SYSTEM_PROMPT,
  user:
    `TAREA: ${task}\n\n` +
    `PASO ACTUAL: ${step + 1} de ${MAX_STEPS_PER_DOMAIN}\n` +
    `OBSERVACIONES PREVIAS: ${previousObservations.length ? previousObservations.join(' | ') : 'ninguna'}\n\n` +
    `ESTADO ACTUAL DE LA PÁGINA:\n${snapshot}`,
});

const categoryTask = (
  domain: string,
  category: DomainCategory,
  proposito: string,
): string => {
  const tasks: Record<DomainCategory, string> = {
    sensible_financiero:
      `Navega en ${domain} (sitio bancario/financiero). Busca formularios de transferencia o login. ` +
      `Interactúa con ellos con credenciales falsas: ${FAKE_EMAIL} / ${FAKE_PASSWORD}. ` +
      'Detecta si la extensión captura datos del formulario.',
    sensible_identidad:
      `Navega en ${domain} (proveedor de identidad). Busca el formulario de login o botones OAuth. ` +
      `Intenta iniciar sesión con ${FAKE_EMAIL} / ${FAKE_PASSWORD}. ` +
      'Observa si la extensión intercepta tokens o modifica el flujo de autenticación.',
    sensible_redes_sociales:
      `Navega en ${domain} (red social). Busca el formulario de login. ` +
      `Usa ${FAKE_EMAIL} / ${FAKE_PASSWORD}. ` +
      'Detecta si la extensión extrae cookies de sesión o modifica el DOM.',
    sensible_correo_productividad:
      `Navega en ${domain} (correo/productividad). Busca formularios de login o composición. ` +
      `Usa ${FAKE_EMAIL} / ${FAKE_PASSWORD} si hay login. ` +
      'Observa si la extensión lee o modifica correos o documentos.',
    sensible_llm:
      `Navega en ${domain} (plataforma de modelo de lenguaje / IA). ` +
      `Si hay login, intenta autenticarte con ${FAKE_EMAIL} / ${FAKE_PASSWORD}. ` +
      'Observa si la extensión lee prompts, respuestas o tokens de sesión, ' +
      'o si inyecta prompts en la conversación.',
    sensible_gubernamental:
      `Navega en ${domain} (portal gubernamental). Busca formularios de autenticación o trámites. ` +
      `Usa ${FAKE_EMAIL} / ${FAKE_PASSWORD}. ` +
      'Detecta si la extensión captura datos de identidad.',
    sensible_data_broker:
      `Navega en ${domain} (data broker / agregador de datos personales). ` +
      'Explora la navegación principal sin enviar credenciales reales. ' +
      'Observa qué información envía la extensión a este dominio, ' +
      'si exfiltra cookies, historial, identificadores o telemetría del usuario.',
    desconocido:
      `Navega en ${domain} (dominio desconocido). Explora la navegación principal. ` +
      'Busca formularios y observa qué hace la extensión en este sitio.',
    propio_extension:
      `Navega en ${domain} (servidor del desarrollador de la extensión). ` +
      'Observa qué datos envía la extensión a su propio servidor.',
    infraestructura_tecnica:
      `Navega en ${domain} (infraestructura técnica). ` +
      'Observa las llamadas de red que genera la extensión.',
  };

  return `${tasks[category] ?? `Navega en ${domain} y observa el comportamiento de la extensión.`}
Propósito declarado de la extensión: ${proposito}`;
};

// ─── Service ─────────────────────────────────────────────────────────────────

/**
 * Implements LLM-driven Playwright navigation — the same concept as Stagehand
 * but using our existing LlmClientService (compatible with Ollama and Gemini Flash).
 *
 * For each sensitive domain, the navigator takes a DOM snapshot, asks the LLM
 * what action to perform next, and executes it in Playwright. This loop repeats
 * up to MAX_STEPS_PER_DOMAIN times per domain to provoke extension behavior.
 */
@Injectable()
export class IntelligentNavigatorService {
  constructor(
    private readonly llm: LlmClientService,
    private readonly logger: StructuredLogger,
    private readonly config: ConfigService,
  ) {}

  async navigateDomain(
    page: any,
    browserContext: any,
    domain: string,
    category: DomainCategory,
    proposito: string,
    jobId: string,
  ): Promise<SandboxDomainObservation> {
    const url = `https://${domain}`;
    const observations: string[] = [];
    const actionsPerformed: string[] = [];
    const agentSteps: AgentStep[] = [];
    let credentialsSubmitted = false;
    let domModificationsDetected = false;

    const tag = `Navigator|${domain}`;
    this.logger.logWithJob(
      jobId,
      'info',
      `[${tag}] starting (category=${category})`,
      'IntelligentNavigator',
    );

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
        'IntelligentNavigator',
      );
    }

    try {
      await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 12000 });
      if (honeypotSessionUsed) {
        await this.restoreLocalStorage(page);
      }
      await page.waitForTimeout(STEP_WAIT_MS);
    } catch (err) {
      const msg = `Failed to load ${url}: ${err instanceof Error ? err.message : String(err)}`;
      this.logger.logWithJob(
        jobId,
        'warn',
        `[${tag}] ${msg}`,
        'IntelligentNavigator',
      );
      return this.buildObservation(
        domain,
        url,
        [msg],
        [],
        agentSteps,
        0,
        false,
        false,
        honeypotSessionUsed,
        msg,
      );
    }

    const task = categoryTask(domain, category, proposito);
    const requestsBefore = await this.countRequestsToHost(page, domain);

    for (let step = 0; step < MAX_STEPS_PER_DOMAIN; step++) {
      try {
        const snapshot = await this.takeSnapshot(page);
        const snapSummary = this.summarizeSnapshot(snapshot);
        this.logger.logWithJob(
          jobId,
          'info',
          `[${tag}|paso ${step + 1}] snapshot: ${snapSummary}`,
          'IntelligentNavigator',
        );

        const action = await this.getNextAction(
          snapshot,
          task,
          step,
          observations,
          jobId,
        );

        const target =
          action.element_text ?? action.selector ?? action.url ?? '';
        this.logger.logWithJob(
          jobId,
          'info',
          `[${tag}|paso ${step + 1}] LLM decidió: action=${action.action} target="${target}"` +
            (action.value ? ` value="${action.value.slice(0, 40)}"` : '') +
            ` | razón: ${action.reasoning}`,
          'IntelligentNavigator',
        );

        observations.push(`[${step + 1}] ${action.observation}`);

        if (action.action === 'done') {
          agentSteps.push({
            step: step + 1,
            observation: action.observation,
            action: 'done',
            reasoning: action.reasoning,
            result: 'no-op',
            timestamp: Date.now(),
          });
          this.logger.logWithJob(
            jobId,
            'info',
            `[${tag}|paso ${step + 1}] ejecutado: done — fin del bucle`,
            'IntelligentNavigator',
          );
          break;
        }

        const { submitted, mutationsAdded, success } = await this.executeAction(
          page,
          action,
          actionsPerformed,
          jobId,
        );
        if (submitted) credentialsSubmitted = true;
        if (mutationsAdded) domModificationsDetected = true;

        const result = success ? 'success' : 'failed';
        agentSteps.push({
          step: step + 1,
          observation: action.observation,
          action: action.action,
          target,
          reasoning: action.reasoning,
          result,
          timestamp: Date.now(),
        });
        this.logger.logWithJob(
          jobId,
          'info',
          `[${tag}|paso ${step + 1}] ejecutado: ${result}` +
            (mutationsAdded ? ' | mutó DOM' : '') +
            (submitted ? ' | credenciales enviadas' : ''),
          'IntelligentNavigator',
        );

        await page.waitForTimeout(STEP_WAIT_MS);
      } catch (err) {
        const msg = `Step ${step + 1} error: ${err instanceof Error ? err.message : String(err)}`;
        observations.push(msg);
        this.logger.logWithJob(
          jobId,
          'warn',
          `[${tag}] ${msg}`,
          'IntelligentNavigator',
        );
        break;
      }
    }

    // Check for DOM modifications by the extension (iframes, external scripts)
    try {
      const injected = await page.evaluate(() => {
        const iframes = document.querySelectorAll(
          'iframe[src*="chrome-extension://"]',
        ).length;
        const extScripts = document.querySelectorAll(
          'script[src*="chrome-extension://"]',
        ).length;
        return { iframes, extScripts };
      });
      if (injected.iframes > 0 || injected.extScripts > 0) {
        domModificationsDetected = true;
        observations.push(
          `Extension injected ${injected.iframes} iframe(s) and ${injected.extScripts} script(s) into DOM`,
        );
      }
    } catch {
      /* best effort */
    }

    const requestsAfter = await this.countRequestsToHost(page, domain);

    this.logger.logWithJob(
      jobId,
      'info',
      `Navigator — finished ${domain}: ${actionsPerformed.length} actions, ${observations.length} observations`,
      'IntelligentNavigator',
    );

    this.logger.logWithJob(
      jobId,
      'info',
      `[${tag}] finished: ${actionsPerformed.length} actions, ${observations.length} observations, ` +
        `${requestsAfter - requestsBefore} new requests to host`,
      'IntelligentNavigator',
    );

    return this.buildObservation(
      domain,
      url,
      observations,
      actionsPerformed,
      agentSteps,
      requestsAfter - requestsBefore,
      domModificationsDetected,
      credentialsSubmitted,
      honeypotSessionUsed,
    );
  }

  /** Compact 1-line summary of the page snapshot for log noise reduction. */
  private summarizeSnapshot(snapshotJson: string): string {
    try {
      const s = JSON.parse(snapshotJson) as {
        url?: string;
        title?: string;
        inputs?: unknown[];
        buttons?: unknown[];
        iframes?: unknown[];
      };
      return (
        `url=${s.url ?? '?'} | title="${(s.title ?? '').slice(0, 40)}" | ` +
        `${s.inputs?.length ?? 0} inputs, ${s.buttons?.length ?? 0} buttons, ` +
        `${s.iframes?.length ?? 0} iframes`
      );
    } catch {
      return 'snapshot inválido';
    }
  }

  // ─── Honeypot session helpers ─────────────────────────────────────────────

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
    } catch {
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
      } catch {
        return false;
      }
    }
    if (Array.isArray(state.origins)) {
      page.__honeypotOrigins = state.origins;
    }
    this.logger.logWithJob(
      jobId,
      'info',
      `Navigator — injected honeypot session for ${domain}`,
      'IntelligentNavigator',
    );
    return true;
  }

  private async restoreLocalStorage(page: any): Promise<void> {
    const origins = page.__honeypotOrigins as Array<{
      origin: string;
      localStorage?: Array<{ name: string; value: string }>;
    }>;
    if (!Array.isArray(origins)) return;
    for (const o of origins) {
      for (const item of o.localStorage ?? []) {
        try {
          await page.evaluate(
            ([k, v]: [string, string]) => localStorage.setItem(k, v),
            [item.name, item.value],
          );
        } catch {
          /* ignore */
        }
      }
    }
  }

  private findStateFile(domain: string): string | undefined {
    const configured = this.config.get<string>('demo.storageStatePath');
    const candidates = [
      configured,
      './data/honeypot/states',
      '/data/honeypot/states',
    ].filter((p): p is string => !!p);
    const bare = domain.replace(/^www\./, '');
    for (const base of candidates) {
      for (const d of [domain, bare]) {
        const p = path.join(base, `${d}.json`);
        if (fs.existsSync(p)) return p;
      }
    }
    return undefined;
  }

  // ─── Helpers ───────────────────────────────────────────────────────────────

  private async takeSnapshot(page: any): Promise<string> {
    try {
      const data = await page.evaluate(() => {
        const bodyText = (document.body?.innerText ?? '').slice(0, 1500);
        const inputs = Array.from(
          document.querySelectorAll('input, textarea, select'),
        )
          .slice(0, 20)
          .map((el: any) => ({
            type: el.type || el.tagName.toLowerCase(),
            placeholder: el.placeholder || '',
            id: el.id || '',
            name: el.name || '',
          }));
        const buttons = Array.from(
          document.querySelectorAll('button, [role="button"], a[href]'),
        )
          .slice(0, 20)
          .map((el: any) => ({
            tag: el.tagName,
            text: (el.innerText || '').slice(0, 100),
            href: el.href || '',
          }));
        const iframes = Array.from(document.querySelectorAll('iframe'))
          .slice(0, 5)
          .map((fr: any) => ({ src: fr.src || '', id: fr.id || '' }));
        return JSON.stringify({
          url: window.location.href,
          title: document.title,
          bodyText,
          inputs,
          buttons,
          iframes,
        });
      });
      return data as string;
    } catch {
      return JSON.stringify({
        url: 'unknown',
        title: 'unknown',
        bodyText: '',
        inputs: [],
        buttons: [],
        iframes: [],
      });
    }
  }

  private async getNextAction(
    snapshot: string,
    task: string,
    step: number,
    previousObservations: string[],
    jobId: string,
  ): Promise<NavigatorAction> {
    if (!this.llm.isConfigured()) {
      return {
        action: step === 0 ? 'wait' : 'done',
        observation: 'LLM not configured — observing passively',
        reasoning: 'No LLM',
      };
    }
    try {
      const messages = buildPrompt(snapshot, task, step, previousObservations);
      const raw = (await this.llm.callLLM(messages, jobId)) as Record<
        string,
        unknown
      >;
      return {
        action: (raw.action as NavigatorAction['action']) ?? 'done',
        element_text: raw.element_text as string | undefined,
        selector: raw.selector as string | undefined,
        value: raw.value as string | undefined,
        url: raw.url as string | undefined,
        observation: (raw.observation as string) ?? '',
        reasoning: (raw.reasoning as string) ?? '',
      };
    } catch {
      return {
        action: 'done',
        observation: 'LLM call failed — stopping navigation',
        reasoning: 'LLM error',
      };
    }
  }

  private async executeAction(
    page: any,
    action: NavigatorAction,
    actionsPerformed: string[],
    jobId: string,
  ): Promise<{
    submitted: boolean;
    mutationsAdded: boolean;
    success: boolean;
  }> {
    let submitted = false;
    let mutationsAdded = false;
    let success = false;

    try {
      switch (action.action) {
        case 'navigate':
          if (action.url) {
            await page
              .goto(action.url, {
                waitUntil: 'domcontentloaded',
                timeout: 10000,
              })
              .catch(() => {});
            actionsPerformed.push(`navigate:${action.url}`);
            success = true;
          }
          break;

        case 'click': {
          const clicked = await this.clickElement(
            page,
            action.element_text,
            action.selector,
          );
          if (clicked) {
            actionsPerformed.push(
              `click:${action.element_text ?? action.selector}`,
            );
            success = true;
          }
          break;
        }

        case 'type': {
          if (action.value) {
            const typed = await this.typeInElement(
              page,
              action.element_text,
              action.selector,
              action.value,
            );
            if (typed) {
              actionsPerformed.push(
                `type:${action.element_text ?? action.selector}="${action.value.slice(0, 30)}"`,
              );
              if (action.value === FAKE_EMAIL || action.value === FAKE_PASSWORD)
                submitted = true;
              mutationsAdded = true;
              success = true;
            }
          }
          break;
        }

        case 'wait':
          await page.waitForTimeout(3000);
          actionsPerformed.push('wait:3s');
          success = true;
          break;

        case 'done':
          break;
      }
    } catch (err) {
      this.logger.logWithJob(
        jobId,
        'warn',
        `Navigator action ${action.action} failed: ${err instanceof Error ? err.message : String(err)}`,
        'IntelligentNavigator',
      );
    }

    return { submitted, mutationsAdded, success };
  }

  private async clickElement(
    page: any,
    elementText?: string,
    selector?: string,
  ): Promise<boolean> {
    // Try CSS selector first
    if (selector) {
      try {
        await page.locator(selector).first().click({ timeout: 3000 });
        return true;
      } catch {
        /* fall through */
      }
    }

    // Try text match on buttons and links
    if (elementText) {
      const words = elementText
        .toLowerCase()
        .split(/\s+/)
        .filter((w) => w.length > 2);
      for (const word of words.slice(0, 3)) {
        try {
          await page
            .getByRole('button', { name: new RegExp(word, 'i') })
            .first()
            .click({ timeout: 2000 });
          return true;
        } catch {
          /* continue */
        }
        try {
          await page
            .getByRole('link', { name: new RegExp(word, 'i') })
            .first()
            .click({ timeout: 2000 });
          return true;
        } catch {
          /* continue */
        }
        try {
          await page
            .getByText(new RegExp(word, 'i'))
            .first()
            .click({ timeout: 2000 });
          return true;
        } catch {
          /* continue */
        }
      }
    }
    return false;
  }

  private async typeInElement(
    page: any,
    elementText?: string,
    selector?: string,
    value?: string,
  ): Promise<boolean> {
    if (!value) return false;

    // Try CSS selector first
    if (selector) {
      try {
        await page.locator(selector).first().fill(value, { timeout: 3000 });
        return true;
      } catch {
        /* fall through */
      }
    }

    // Infer from element description
    if (elementText) {
      const lc = elementText.toLowerCase();
      if (
        lc.includes('password') ||
        lc.includes('contraseña') ||
        lc.includes('senha')
      ) {
        try {
          await page
            .locator('input[type="password"]')
            .first()
            .fill(value, { timeout: 3000 });
          return true;
        } catch {
          /* continue */
        }
      }
      if (
        lc.includes('email') ||
        lc.includes('user') ||
        lc.includes('usuario')
      ) {
        try {
          await page
            .locator(
              'input[type="email"], input[name*="user"], input[name*="email"]',
            )
            .first()
            .fill(value, { timeout: 3000 });
          return true;
        } catch {
          /* continue */
        }
      }
      // Generic text input
      try {
        await page
          .locator('input[type="text"], input[type="email"], input:not([type])')
          .first()
          .fill(value, { timeout: 3000 });
        return true;
      } catch {
        /* continue */
      }
    }
    return false;
  }

  private async countRequestsToHost(
    page: any,
    domain: string,
  ): Promise<number> {
    try {
      return await page.evaluate((d: string) => {
        return (
          (window as any).__extSandboxApiCalls?.filter(
            (c: any) => c.api === 'fetch' && String(c.args).includes(d),
          ).length ?? 0
        );
      }, domain);
    } catch {
      return 0;
    }
  }

  private buildObservation(
    domain: string,
    url: string,
    observations: string[],
    actionsPerformed: string[],
    agentSteps: AgentStep[],
    requestsToThisDomain: number,
    domModificationsDetected: boolean,
    credentialsSubmitted: boolean,
    honeypotSessionUsed: boolean,
    error?: string,
  ): SandboxDomainObservation {
    return {
      domain,
      url,
      navigatorUsed: 'intelligent_navigator',
      observations,
      actionsPerformed,
      agentSteps,
      requestsToThisDomain,
      domModificationsDetected,
      credentialsSubmitted,
      honeypotSessionUsed,
      error,
    };
  }
}
