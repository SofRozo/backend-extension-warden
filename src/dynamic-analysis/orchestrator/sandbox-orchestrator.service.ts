import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { StructuredLogger } from '../../common/logger/logger.service.js';
import {
  NetworkInterceptorService,
  EvidenceCollector,
} from '../network-interceptor/network-interceptor.service.js';
import {
  DetonationStrategyService,
  DetonationPlan,
} from '../detonation-strategies/detonation-strategy.service.js';
import { IntelligentNavigatorService } from '../navigator/intelligent-navigator.service.js';
import { StagehandService } from '../navigator/stagehand.service.js';
import {
  StaticAnalysisResult,
  DynamicAnalysisResult,
  AgentAnalysisResult,
} from '../../common/interfaces/analysis.interfaces.js';
import { DetonationStrategy } from '../../common/enums/risk-level.enum.js';
import * as fs from 'fs';
import * as path from 'path';
import * as http from 'http';

@Injectable()
export class SandboxOrchestratorService {
  constructor(
    private readonly config: ConfigService,
    private readonly logger: StructuredLogger,
    private readonly networkInterceptor: NetworkInterceptorService,
    private readonly detonationStrategy: DetonationStrategyService,
    private readonly intelligentNavigator: IntelligentNavigatorService,
    private readonly stagehand: StagehandService,
  ) { }

  async executeDynamicAnalysis(
    extensionPath: string,
    extensionId: string,
    staticResult: StaticAnalysisResult,
    jobId: string,
    agentAnalysis?: AgentAnalysisResult,
  ): Promise<DynamicAnalysisResult> {
    const timeoutMs =
      this.config.get<number>('analysis.dynamicTimeoutMs') || 180000;
    const demoMode = this.config.get<boolean>('demo.enabled') || false;
    const demoSlowMo = this.config.get<number>('demo.slowMo') || 800;
    const startTime = Date.now();

    this.logger.logWithJob(
      jobId,
      'info',
      `Starting dynamic analysis${demoMode ? ' [DEMO MODE — headed browser]' : ''}`,
      'SandboxOrchestrator',
    );

    const plans = this.detonationStrategy.selectStrategy(staticResult);

    // If Agent 2 produced a categorized domain list for Playwright, inject a
    // DIRECT_NAVIGATION plan so that list always gets exercised — even when the
    // static domain classifier found no Level-1 public domains to navigate.
    // executeDirectNavigation reads dominios_para_playwright from agentAnalysis
    // directly, so targetUrls can be empty here.
    const agent2Domains = (agentAnalysis?.agent2 as any)?.dominios_para_playwright ?? [];
    const hasDirectNav = plans.some(p => p.strategy === DetonationStrategy.DIRECT_NAVIGATION);
    if (agent2Domains.length > 0 && !hasDirectNav) {
      plans.unshift({
        strategy: DetonationStrategy.DIRECT_NAVIGATION,
        targetUrls: [],
        waitTimeMs: 10000,
      });
    }

    this.logger.logWithJob(
      jobId,
      'info',
      `Selected ${plans.length} detonation plan(s)${agent2Domains.length > 0 ? ` (${agent2Domains.length} domains from Agent 2)` : ''}`,
      'SandboxOrchestrator',
    );

    const collector = this.networkInterceptor.createEvidenceCollector(extensionId);
    const domainObservations: import('../../common/interfaces/analysis.interfaces.js').SandboxDomainObservation[] = [];
    let timedOut = false;
    let primaryStrategy = plans[0]?.strategy || DetonationStrategy.PASSIVE_TRIGGER;

    // Baseline: visit target URLs without the extension to capture natural page traffic.
    // Requests seen in the baseline are reclassified as 'browser' origin, eliminating
    // false positives caused by normal CDN/API calls made by the visited pages.
    if (!demoMode) {
      const urlsForBaseline = [
        ...new Set(
          plans
            .filter((p) => p.strategy !== DetonationStrategy.DOM_FALSIFICATION)
            .flatMap((p) => p.targetUrls),
        ),
      ];
      if (urlsForBaseline.length > 0) {
        const { hosts, mutations } = await this.captureBaseline(urlsForBaseline, jobId);
        collector.setBaseline(hosts, mutations);
      }
    }

    try {
      const { chromium } = await import('playwright');

      const browserArgs = [
        `--disable-extensions-except=${extensionPath}`,
        `--load-extension=${extensionPath}`,
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
      ];

      if (!demoMode) {
        browserArgs.push('--headless=new');
      }

      const browser = await chromium.launchPersistentContext(
        '',
        {
          headless: demoMode ? false : true,
          slowMo: demoMode ? demoSlowMo : 0,
          args: browserArgs,
          timeout: 30000,
          // Stealth: present as a real desktop Chrome rather than HeadlessChrome
          // so anti-bot heuristics on Instagram/Meta/Google don't reject the
          // injected session immediately.
          userAgent:
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ' +
            '(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
          viewport: { width: 1920, height: 1080 },
          locale: 'es-CO',
          timezoneId: 'America/Bogota',
        },
      );

      // Stealth init: scrub the most common automation fingerprints BEFORE any
      // page script runs in this context. Applied once at the context level so
      // every newPage() inherits it.
      await browser.addInitScript(this.buildStealthScript()).catch(() => { });

      // Verify the extension installed correctly before running any analysis.
      // If the extension's manifest is not reachable at chrome-extension://<id>/manifest.json
      // it means it failed to load (e.g. missing key, CRX parse error) and the
      // entire dynamic analysis would produce false-negative results.
      const extensionInstalled = await this.verifyExtensionInstalled(browser, extensionId, jobId);
      if (!extensionInstalled) {
        this.logger.logWithJob(
          jobId,
          'error',
          `Extension ${extensionId} failed to install — dynamic analysis aborted to prevent false negatives`,
          'SandboxOrchestrator',
        );
        await browser.close().catch(() => { });
        return {
          strategy: primaryStrategy,
          evidence: collector.getEvidence(),
          duration: Date.now() - startTime,
          timedOut: false,
          domainObservations: undefined,
        };
      }

      // Instrument the extension's background service worker so we capture
      // chrome.* API calls and SW-originated fetches that page-level
      // addInitScript cannot reach (chrome.* is undefined in normal pages).
      this.instrumentExtensionServiceWorker(browser, extensionId, collector, jobId, demoMode);

      try {
        for (const plan of plans) {
          if (Date.now() - startTime > timeoutMs) {
            timedOut = true;
            this.logger.logWithJob(
              jobId,
              'warn',
              'Dynamic analysis timeout reached',
              'SandboxOrchestrator',
            );
            break;
          }

          await this.executePlan(
            browser,
            plan,
            collector,
            extensionId,
            extensionPath,
            jobId,
            demoMode,
            agentAnalysis,
            domainObservations,
          );
        }
      } finally {
        await browser.close().catch(() => { });
      }
    } catch (err) {
      this.logger.logWithJob(
        jobId,
        'error',
        `Dynamic analysis error: ${err instanceof Error ? err.message : String(err)}`,
        'SandboxOrchestrator',
      );
    }

    const duration = Date.now() - startTime;

    return {
      strategy: primaryStrategy,
      evidence: collector.getEvidence(),
      duration,
      timedOut,
      domainObservations: domainObservations.length > 0 ? domainObservations : undefined,
    };
  }

  private async executePlan(
    browser: any,
    plan: DetonationPlan,
    collector: EvidenceCollector,
    extensionId: string,
    extensionPath: string,
    jobId: string,
    demoMode: boolean,
    agentAnalysis?: AgentAnalysisResult,
    domainObservations?: import('../../common/interfaces/analysis.interfaces.js').SandboxDomainObservation[],
  ): Promise<void> {
    this.logger.logWithJob(
      jobId,
      'info',
      `Executing strategy: ${plan.strategy}`,
      'SandboxOrchestrator',
    );

    collector.setContext(plan.strategy);

    switch (plan.strategy) {
      case DetonationStrategy.STATE_INJECTION:
        await this.executeStateInjection(browser, plan, collector, extensionId, extensionPath, jobId, demoMode);
        break;
      case DetonationStrategy.PASSIVE_TRIGGER:
        await this.executePassiveTrigger(browser, plan, collector, extensionId, extensionPath, jobId, demoMode);
        break;
      case DetonationStrategy.DOM_FALSIFICATION:
        await this.executeDomFalsification(browser, plan, collector, extensionId, extensionPath, jobId, demoMode);
        break;
      case DetonationStrategy.DIRECT_NAVIGATION:
        await this.executeDirectNavigation(browser, plan, collector, extensionId, extensionPath, jobId, demoMode, agentAnalysis, domainObservations);
        break;
    }
  }

  private async executeStateInjection(
    browser: any,
    plan: DetonationPlan,
    collector: EvidenceCollector,
    extensionId: string,
    extensionPath: string,
    jobId: string,
    demoMode: boolean,
  ): Promise<void> {
    for (const url of plan.targetUrls) {
      try {
        const page = await browser.newPage();
        this.setupPageInterception(page, collector, demoMode);

        if (plan.storageStatePath) {
          const stateData = JSON.parse(
            fs.readFileSync(plan.storageStatePath, 'utf-8'),
          );
          if (stateData.cookies) {
            await browser.addCookies(stateData.cookies);
          }
          if (demoMode) {
            // storageState also contains localStorage — restore it after first navigation
            plan['_demoStateData'] = stateData;
          }
        }

        await this.setupScreenshots(page, jobId, DetonationStrategy.STATE_INJECTION, collector);
        await this.setupApiInterception(page, extensionId, demoMode);
        await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 15000 });

        if (demoMode && plan['_demoStateData']?.origins) {
          // Restore localStorage after navigation
          for (const origin of plan['_demoStateData'].origins) {
            for (const item of origin.localStorage ?? []) {
              await page.evaluate(
                ([k, v]: [string, string]) => localStorage.setItem(k, v),
                [item.name, item.value],
              ).catch(() => { });
            }
          }
          await this.overlayLog(page, '💉 SESIÓN', 'Cookies + localStorage honeypot inyectados', 'info');
        }

        await this.injectMonitoringScripts(page);
        await this.interactWithExtension(browser, page, extensionId, extensionPath, demoMode);

        await page.waitForTimeout(plan.waitTimeMs);
        await this.takePageScreenshot(page, 'final', collector);
        await this.collectPageEvidence(page, collector);
        await page.close();
      } catch (err) {
        this.logger.logWithJob(
          jobId,
          'warn',
          `State injection failed for ${url}: ${err instanceof Error ? err.message : String(err)}`,
          'SandboxOrchestrator',
        );
      }
    }
  }

  private async executePassiveTrigger(
    browser: any,
    plan: DetonationPlan,
    collector: EvidenceCollector,
    extensionId: string,
    extensionPath: string,
    jobId: string,
    demoMode: boolean,
  ): Promise<void> {
    for (const url of plan.targetUrls) {
      try {
        const page = await browser.newPage();
        this.setupPageInterception(page, collector, demoMode);

        await this.setupScreenshots(page, jobId, DetonationStrategy.PASSIVE_TRIGGER, collector);
        await this.setupApiInterception(page, extensionId, demoMode);
        await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 15000 });
        await this.injectMonitoringScripts(page);
        await this.interactWithExtension(browser, page, extensionId, extensionPath, demoMode);

        await page.waitForTimeout(plan.waitTimeMs);
        await this.takePageScreenshot(page, 'final', collector);
        await this.collectPageEvidence(page, collector);
        await page.close();
      } catch (err) {
        this.logger.logWithJob(
          jobId,
          'warn',
          `Passive trigger failed for ${url}: ${err instanceof Error ? err.message : String(err)}`,
          'SandboxOrchestrator',
        );
      }
    }
  }

  private async executeDomFalsification(
    browser: any,
    plan: DetonationPlan,
    collector: EvidenceCollector,
    extensionId: string,
    extensionPath: string,
    jobId: string,
    demoMode: boolean,
  ): Promise<void> {
    if (!plan.fakeHtmlContent) return;

    let server: http.Server | null = null;
    try {
      const port = 18900 + Math.floor(Math.random() * 100);
      server = http.createServer((_req, res) => {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(plan.fakeHtmlContent);
      });

      await new Promise<void>((resolve) => server!.listen(port, resolve));

      const page = await browser.newPage();
      this.setupPageInterception(page, collector, demoMode);

      await this.setupScreenshots(page, jobId, DetonationStrategy.DOM_FALSIFICATION, collector);
      await this.setupApiInterception(page, extensionId, demoMode);
      await page.goto(`http://localhost:${port}`, {
        waitUntil: 'domcontentloaded',
        timeout: 10000,
      });
      await this.injectMonitoringScripts(page);
      await this.interactWithExtension(browser, page, extensionId, extensionPath, demoMode);

      await page.waitForTimeout(plan.waitTimeMs);
      await this.takePageScreenshot(page, 'final', collector);
      await this.collectPageEvidence(page, collector);
      await page.close();
    } catch (err) {
      this.logger.logWithJob(
        jobId,
        'warn',
        `DOM falsification failed: ${err instanceof Error ? err.message : String(err)}`,
        'SandboxOrchestrator',
      );
    } finally {
      if (server) {
        server.close();
      }
    }
  }

  private async executeDirectNavigation(
    browser: any,
    plan: DetonationPlan,
    collector: EvidenceCollector,
    extensionId: string,
    extensionPath: string,
    jobId: string,
    demoMode: boolean,
    agentAnalysis?: AgentAnalysisResult,
    domainObservations?: import('../../common/interfaces/analysis.interfaces.js').SandboxDomainObservation[],
  ): Promise<void> {
    const agent1 = agentAnalysis?.agent1 as any;
    const proposito = agent1?.proposito || 'Analizar comportamiento de la extensión';

    // Agent 2 domains take priority; fall back to plan URLs when Agent 2 didn't run.
    const agent2 = agentAnalysis?.agent2 as any;
    const targets: Array<{ domain: string; category: string }> =
      agent2?.dominios_para_playwright?.length > 0
        ? agent2.dominios_para_playwright
        : plan.targetUrls
            .map((url: string) => {
              try {
                return { domain: new URL(url).hostname, category: 'desconocido' };
              } catch {
                return { domain: url, category: 'desconocido' };
              }
            })
            .filter((t: { domain: string }) => !!t.domain);

    const useStagehand = this.config.get<boolean>('analysis.useStagehand') || false;

    for (const target of targets) {
      try {
        const page = await browser.newPage();
        this.setupPageInterception(page, collector, demoMode);
        await this.setupScreenshots(page, jobId, DetonationStrategy.DIRECT_NAVIGATION, collector);
        await this.setupApiInterception(page, extensionId, demoMode);

        let observation;
        if (useStagehand) {
          observation = await this.stagehand.navigateDomain(
            page, target.domain, target.category as any, proposito, jobId,
          );
        } else {
          observation = await this.intelligentNavigator.navigateDomain(
            page, target.domain, target.category as any, proposito, jobId,
          );
        }

        // Log observations AND store them for Agent 4
        for (const obs of observation.observations) {
          collector.onLog('IntelligentNavigator', obs, 'info');
        }
        domainObservations?.push(observation);

        await page.close();
      } catch (err) {
        this.logger.logWithJob(
          jobId,
          'warn',
          `Dynamic navigation failed for ${target.domain}: ${err instanceof Error ? err.message : String(err)}`,
          'SandboxOrchestrator',
        );
        domainObservations?.push({
          domain: target.domain,
          url: `https://${target.domain}`,
          observations: [`Error: ${err instanceof Error ? err.message : String(err)}`],
          actionsPerformed: [],
          requestsToThisDomain: 0,
          domModificationsDetected: false,
          credentialsSubmitted: false,
          error: err instanceof Error ? err.message : String(err),
        });
      }
    }
  }

  private async interactWithExtension(
    browser: any,
    page: any,
    extensionId: string,
    extensionPath: string,
    demoMode: boolean,
  ): Promise<void> {
    // 1. Try to open the extension popup
    try {
      const manifestPath = path.join(extensionPath, 'manifest.json');
      if (fs.existsSync(manifestPath)) {
        const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf-8'));
        const popupPath = manifest.action?.default_popup || manifest.browser_action?.default_popup || manifest.page_action?.default_popup;
        if (popupPath) {
          const popupUrl = `chrome-extension://${extensionId}/${popupPath}`;
          const popupPage = await browser.newPage();
          await popupPage.goto(popupUrl, { waitUntil: 'domcontentloaded', timeout: 5000 });
          if (demoMode) {
            await this.overlayLog(page, '🖱️ POPUP', 'Extension popup opened and interacted', 'info');
          }
          await popupPage.waitForTimeout(2000);
          await popupPage.close();
        }
      }
    } catch { /* ignore interaction failures */ }

    // 2. Perform some generic interaction on the main page to trigger event listeners
    try {
      await page.mouse.move(100, 100);
      await page.mouse.down();
      await page.mouse.up();
      await page.keyboard.press('Shift');
    } catch { /* ignore */ }
  }

  // ─── Extension installation verification ──────────────────────────────────

  /**
   * Verifies the extension loaded correctly by navigating to its manifest URL.
   * For CRX files downloaded from the Web Store, the internal Chrome extension ID
   * matches the Web Store ID, so chrome-extension://<id>/manifest.json is reachable
   * if and only if the extension installed without error.
   */
  private async verifyExtensionInstalled(
    browser: any,
    extensionId: string,
    jobId: string,
  ): Promise<boolean> {
    try {
      const page = await browser.newPage();
      const manifestUrl = `chrome-extension://${extensionId}/manifest.json`;
      const response = await page.goto(manifestUrl, { timeout: 5000 }).catch(() => null);
      await page.close().catch(() => { });
      if (response && response.ok()) {
        this.logger.logWithJob(jobId, 'info', `Extension ${extensionId} verified as installed`, 'SandboxOrchestrator');
        return true;
      }
    } catch {
      // Fall through to warning below
    }
    this.logger.logWithJob(
      jobId,
      'warn',
      `Could not verify extension ${extensionId} via chrome-extension:// — proceeding with analysis (unpacked extensions use a generated ID)`,
      'SandboxOrchestrator',
    );
    // Return true for unpacked extensions: their ID is generated from the path,
    // not the Web Store ID, so the URL check will fail even when loaded correctly.
    // The browser launch args already ensure the extension path is loaded.
    return true;
  }

  // ─── Differential baseline ────────────────────────────────────────────────

  private async captureBaseline(urls: string[], jobId: string): Promise<{ hosts: Set<string>, mutations: Set<string> }> {
    const hosts = new Set<string>();
    const mutations = new Set<string>();
    this.logger.logWithJob(jobId, 'info', `Capturing baseline for ${urls.length} URL(s)`, 'SandboxOrchestrator');

    try {
      const { chromium } = await import('playwright');
      const browser = await chromium.launchPersistentContext('', {
        headless: true,
        args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage'],
        timeout: 15000,
      });

      for (const url of urls) {
        try {
          const page = await browser.newPage();
          page.on('request', (req: any) => {
            try {
              const hostname = new URL(req.url()).hostname;
              if (hostname) hosts.add(hostname);
            } catch { /* ignore */ }
          });

          // Record natural DOM mutations on the target page
          await page.exposeFunction('__baselineMutation', (type: string, target: string) => {
            mutations.add(`${type}:${target}`);
          });

          await page.addInitScript(() => {
            const observer = new MutationObserver((list) => {
              for (const m of list) {
                const tag = (m.target as HTMLElement).tagName || 'unknown';
                (window as any).__baselineMutation(m.type, tag);
              }
            });
            observer.observe(document, { childList: true, subtree: true, attributes: true });
          });

          await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 8000 });
          await page.waitForTimeout(3000); // Wait for post-load mutations (ads, trackers)
          await page.close();
        } catch { /* best effort per URL */ }
      }

      await browser.close().catch(() => { });
    } catch (err) {
      this.logger.logWithJob(
        jobId, 'warn',
        `Baseline capture failed (analysis will continue without it): ${err instanceof Error ? err.message : String(err)}`,
        'SandboxOrchestrator',
      );
    }

    this.logger.logWithJob(jobId, 'info', `Baseline captured: ${hosts.size} host(s), ${mutations.size} mutation pattern(s)`, 'SandboxOrchestrator');
    return { hosts, mutations };
  }

  // ─── Demo overlay helpers ──────────────────────────────────────────────────

  private async overlayLog(
    page: any,
    type: string,
    detail: string,
    severity: string,
  ): Promise<void> {
    await page.evaluate(
      ([t, d, s]: [string, string, string]) => {
        const fn = (window as any).__extSandboxAddEvent;
        if (typeof fn === 'function') fn(t, d, s);
      },
      [type, detail, severity],
    ).catch(() => { });
  }

  // ─── Page setup helpers ───────────────────────────────────────────────────

  private async setupScreenshots(
    page: any,
    jobId: string,
    strategyName: string,
    collector: EvidenceCollector,
  ): Promise<void> {
    const baseDir =
      this.config.get<string>('analysis.screenshotsDir') ||
      '/tmp/ext-sandbox/screenshots';
    const dir = path.join(baseDir, jobId);
    fs.mkdirSync(dir, { recursive: true });
    try { fs.chmodSync(dir, 0o777); } catch { } // Ensure API can read it

    let screenshotIndex = 0;

    await page.exposeFunction(
      '__extSandboxCriticalMutation',
      async (reason: string) => {
        const filePath = path.join(
          dir,
          `${strategyName}_critical_${screenshotIndex++}.png`,
        );
        try {
          await page.screenshot({ path: filePath, fullPage: false });
          try { fs.chmodSync(filePath, 0o666); } catch { }
          collector.addScreenshot(filePath);
        } catch {
          // Page may have navigated between detection and screenshot
        }
      },
    );

    (page as any).__screenshotDir = dir;
    (page as any).__strategyName = strategyName;
    (page as any).__screenshotIndex = () => screenshotIndex++;
  }

  private async takePageScreenshot(
    page: any,
    label: string,
    collector: EvidenceCollector,
  ): Promise<void> {
    const dir: string = (page as any).__screenshotDir;
    const strategy: string = (page as any).__strategyName ?? 'unknown';
    const getIndex: () => number = (page as any).__screenshotIndex ?? (() => 0);
    if (!dir) return;

    const filePath = path.join(dir, `${strategy}_${getIndex()}_${label}.png`);
    try {
      await page.screenshot({ path: filePath, fullPage: false });
      try { fs.chmodSync(filePath, 0o666); } catch { }
      collector.addScreenshot(filePath);
    } catch {
      // Best effort
    }
  }

  private async setupApiInterception(page: any, extensionId: string, demoMode: boolean): Promise<void> {
    const overlayScript = demoMode ? this.buildOverlayScript(extensionId) : '';

    await page.addInitScript((params: { overlay: string; demo: boolean }) => {
      // ── Demo overlay (injected only in DEMO_MODE) ──────────────────────────
      if (params.overlay) {
        // eslint-disable-next-line no-new-func
        new Function(params.overlay)();
      }

      // ── Chrome API proxy (always active) ──────────────────────────────────
      (window as any).__extSandboxApiCalls = [];

      const record = (api: string, args: unknown[]) => {
        try {
          const serialized = JSON.stringify(args).substring(0, 2000);
          (window as any).__extSandboxApiCalls.push({
            api,
            args: serialized,
            timestamp: Date.now(),
          });
        } catch {
          (window as any).__extSandboxApiCalls.push({
            api,
            args: '[unserializable]',
            timestamp: Date.now(),
          });
        }
        if (params.demo && (window as any).__extSandboxAddEvent) {
          (window as any).__extSandboxAddEvent('🟡 API', api, 'medium');
        }
      };

      if ((window as any).chrome?.storage?.local) {
        const orig = (window as any).chrome.storage.local;
        (window as any).chrome.storage.local = new Proxy(orig, {
          get(target: any, prop: string) {
            const fn = target[prop];
            if (typeof fn !== 'function') return fn;
            return (...args: unknown[]) => {
              record(`chrome.storage.local.${prop}`, args);
              return fn.apply(target, args);
            };
          },
        });
      }

      if ((window as any).chrome?.storage?.sync) {
        const orig = (window as any).chrome.storage.sync;
        (window as any).chrome.storage.sync = new Proxy(orig, {
          get(target: any, prop: string) {
            const fn = target[prop];
            if (typeof fn !== 'function') return fn;
            return (...args: unknown[]) => {
              record(`chrome.storage.sync.${prop}`, args);
              return fn.apply(target, args);
            };
          },
        });
      }

      if ((window as any).chrome?.runtime?.sendMessage) {
        const orig = (window as any).chrome.runtime.sendMessage.bind(
          (window as any).chrome.runtime,
        );
        (window as any).chrome.runtime.sendMessage = (...args: unknown[]) => {
          record('chrome.runtime.sendMessage', args);
          return orig(...args);
        };
      }

      if ((window as any).chrome?.tabs) {
        for (const method of ['query', 'sendMessage', 'update', 'create']) {
          const orig = (window as any).chrome.tabs[method];
          if (typeof orig === 'function') {
            (window as any).chrome.tabs[method] = (...args: unknown[]) => {
              record(`chrome.tabs.${method}`, args);
              return orig.apply((window as any).chrome.tabs, args);
            };
          }
        }
      }

      if ((window as any).chrome?.cookies) {
        for (const method of ['get', 'getAll', 'set', 'remove']) {
          const orig = (window as any).chrome.cookies[method];
          if (typeof orig === 'function') {
            (window as any).chrome.cookies[method] = (...args: unknown[]) => {
              record(`chrome.cookies.${method}`, args);
              return orig.apply((window as any).chrome.cookies, args);
            };
          }
        }
      }

      const origFetch = window.fetch.bind(window);
      window.fetch = (input: RequestInfo | URL, init?: RequestInit) => {
        const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
        record('fetch', [url, { method: init?.method, bodyPreview: String(init?.body ?? '').substring(0, 500) }]);
        return origFetch(input, init);
      };

      const OrigXHR = window.XMLHttpRequest;
      (window as any).XMLHttpRequest = class extends OrigXHR {
        open(method: string, url: string) {
          record('XMLHttpRequest.open', [method, url]);
          return super.open(method, url);
        }
      };
    }, { overlay: overlayScript, demo: demoMode });
  }

  private setupPageInterception(page: any, collector: EvidenceCollector, demoMode: boolean): void {
    page.on('request', (request: any) => {
      try {
        const url: string = request.url();
        const method: string = request.method();
        const headers: Record<string, string> = request.headers();
        const body: string | undefined = request.postData();
        const initiator: string | undefined = request.frame()?.url();

        collector.onNetworkRequest(url, method, headers, body, initiator);

        // In demo mode, push extension-originated requests into the overlay
        if (demoMode) {
          const isExtension =
            url.startsWith('chrome-extension://') ||
            (initiator?.startsWith('chrome-extension://') ?? false);
          if (isExtension || (!url.startsWith('chrome://') && !url.startsWith('data:'))) {
            let label = url;
            try { label = new URL(url).hostname; } catch { label = url.substring(0, 60); }
            const severity = isExtension ? 'critical' : 'info';
            const icon = isExtension ? '🔴 RED EXT' : '🌐 RED';
            page.evaluate(
              ([t, d, s]: [string, string, string]) => {
                const fn = (window as any).__extSandboxAddEvent;
                if (typeof fn === 'function') fn(t, d, s);
              },
              [icon, label, severity],
            ).catch(() => { });
          }
        }
      } catch {
        // Best effort
      }
    });
  }

  private async collectPageEvidence(page: any, collector: EvidenceCollector): Promise<void> {
    try {
      const mutations: any[] = await page.evaluate(
        () => (window as any).__extSandboxMutations || [],
      );
      for (const m of mutations) {
        collector.onDomMutation(m.type, m.target);
      }

      const keyEvents: any[] = await page.evaluate(
        () => (window as any).__extSandboxKeyEvents || [],
      );
      for (const ke of keyEvents) {
        collector.onKeyboardEvent(ke.type, ke.key, ke.target);
      }

      const apiCalls: any[] = await page.evaluate(
        () => (window as any).__extSandboxApiCalls || [],
      );
      for (const call of apiCalls) {
        collector.onApiCall(call.api, call.args);
      }
    } catch {
      // Page may have navigated or been closed
    }
  }

  private async injectMonitoringScripts(page: any): Promise<void> {
    try {
      await page.evaluate(() => {
        const observer = new MutationObserver((mutations) => {
          (window as any).__extSandboxMutations =
            (window as any).__extSandboxMutations || [];

          for (const mutation of mutations) {
            const tag = (mutation.target as HTMLElement).tagName || 'unknown';
            (window as any).__extSandboxMutations.push({
              type: mutation.type,
              target: tag,
              addedNodes: mutation.addedNodes.length,
              removedNodes: mutation.removedNodes.length,
              timestamp: Date.now(),
            });

            mutation.addedNodes.forEach((node) => {
              const el = node as HTMLElement;
              if (!el.tagName) return;
              const nodeName = el.tagName.toLowerCase();
              const isCritical =
                (nodeName === 'script' && (el as HTMLScriptElement).src) ||
                nodeName === 'iframe';
              if (isCritical) {
                const reason = nodeName === 'iframe' ? 'iframe' : 'script';
                if ((window as any).__extSandboxCriticalMutation) {
                  (window as any).__extSandboxCriticalMutation(reason).catch(() => { });
                }
                if ((window as any).__extSandboxAddEvent) {
                  (window as any).__extSandboxAddEvent(
                    '🟠 DOM',
                    `<${nodeName}> inyectado`,
                    'high',
                  );
                }
              }
            });
          }
        });

        observer.observe(document.body, {
          childList: true,
          subtree: true,
          attributes: true,
          characterData: true,
        });

        (window as any).__extSandboxKeyEvents = [];
        for (const evtType of ['keydown', 'keyup', 'keypress']) {
          document.addEventListener(
            evtType,
            (e: Event) => {
              const ke = e as globalThis.KeyboardEvent;
              (window as any).__extSandboxKeyEvents.push({
                type: evtType,
                key: ke.key,
                target: (ke.target as HTMLElement)?.tagName,
                timestamp: Date.now(),
              });
            },
            true,
          );
        }

        // Show current page in overlay
        if ((window as any).__extSandboxAddEvent) {
          (window as any).__extSandboxAddEvent(
            '🌐 CARGADO',
            window.location.hostname || window.location.href.substring(0, 50),
            'info',
          );
        }
      });
    } catch {
      // Page might have navigated
    }
  }

  // ─── Service worker instrumentation ───────────────────────────────────────
  // chrome.* APIs only exist inside extension contexts (background SW, popup,
  // options). page.addInitScript runs in the page's main world where those
  // APIs are undefined, so it never catches anything. We attach to the
  // extension's service worker instead and proxy chrome.storage / chrome.tabs
  // / chrome.cookies / chrome.runtime.sendMessage / fetch / XHR. Each call is
  // emitted as a sentinel console.log we forward into the EvidenceCollector.

  private instrumentExtensionServiceWorker(
    browser: any,
    extensionId: string,
    collector: EvidenceCollector,
    jobId: string,
    demoMode: boolean,
  ): void {
    const swUrlPrefix = `chrome-extension://${extensionId}/`;

    // Catch SWs that register after we attach
    browser.on('serviceworker', (sw: any) => {
      if (typeof sw.url === 'function' ? sw.url().startsWith(swUrlPrefix) : false) {
        this.attachToServiceWorker(sw, collector, jobId, demoMode).catch(() => { });
      } else if (sw.url && typeof sw.url === 'string' && sw.url.startsWith(swUrlPrefix)) {
        this.attachToServiceWorker(sw, collector, jobId, demoMode).catch(() => { });
      }
    });

    // Catch SWs that already exist by the time we attach (best effort: SW may
    // not be registered yet when launchPersistentContext returns; the listener
    // above covers later registrations).
    try {
      const existing: any[] = browser.serviceWorkers?.() ?? [];
      for (const sw of existing) {
        const url = typeof sw.url === 'function' ? sw.url() : sw.url;
        if (typeof url === 'string' && url.startsWith(swUrlPrefix)) {
          this.attachToServiceWorker(sw, collector, jobId, demoMode).catch(() => { });
        }
      }
    } catch {
      // Older Playwright versions or context closed
    }
  }

  private async attachToServiceWorker(
    sw: any,
    collector: EvidenceCollector,
    jobId: string,
    demoMode: boolean,
  ): Promise<void> {
    const swUrl: string = typeof sw.url === 'function' ? sw.url() : sw.url;

    this.logger.logWithJob(
      jobId,
      'info',
      `Instrumenting extension service worker: ${swUrl}`,
      'SandboxOrchestrator',
    );

    // Forward sentinel console messages from the SW into the collector
    sw.on?.('console', (msg: any) => {
      try {
        const text: string = typeof msg.text === 'function' ? msg.text() : String(msg);
        if (!text.startsWith('[SANDBOX_API]')) return;
        const payload = JSON.parse(text.substring('[SANDBOX_API]'.length).trim());
        if (payload.kind === 'api') {
          collector.onApiCall(payload.api, payload.args ?? '');
        } else if (payload.kind === 'fetch') {
          collector.onNetworkRequest(
            payload.url,
            payload.method ?? 'GET',
            payload.headers ?? {},
            payload.body,
            swUrl,
            true,
          );
        }
      } catch {
        // Best effort
      }
    });

    // Inject the wrapper. evaluate() runs the function in the SW's global scope.
    try {
      await sw.evaluate(this.buildServiceWorkerWrapper());
    } catch (err) {
      this.logger.logWithJob(
        jobId,
        'warn',
        `SW wrapper injection failed: ${err instanceof Error ? err.message : String(err)}`,
        'SandboxOrchestrator',
      );
    }

    void demoMode; // future: surface SW activity in the page overlay too
  }

  private buildServiceWorkerWrapper(): string {
    // String form so it survives serialization across the CDP boundary.
    return `(() => {
  if (self.__extSandboxInstrumented) return;
  self.__extSandboxInstrumented = true;

  function emit(payload) {
    try { console.log('[SANDBOX_API] ' + JSON.stringify(payload)); } catch (e) {}
  }

  function safeArgs(args) {
    try { return JSON.stringify(Array.from(args)).substring(0, 2000); }
    catch (e) { return '[unserializable]'; }
  }

  function wrapNamespace(nsPath) {
    const parts = nsPath.split('.');
    let obj = self;
    for (const p of parts) {
      if (!obj || typeof obj[p] === 'undefined') return;
      obj = obj[p];
    }
    if (!obj || typeof obj !== 'object') return;
    for (const key of Object.keys(obj)) {
      const orig = obj[key];
      if (typeof orig !== 'function') continue;
      obj[key] = function() {
        emit({ kind: 'api', api: nsPath + '.' + key, args: safeArgs(arguments) });
        return orig.apply(obj, arguments);
      };
    }
  }

  // chrome.* surface most commonly abused by malicious extensions
  wrapNamespace('chrome.storage.local');
  wrapNamespace('chrome.storage.sync');
  wrapNamespace('chrome.storage.session');
  wrapNamespace('chrome.cookies');
  wrapNamespace('chrome.tabs');
  wrapNamespace('chrome.scripting');
  wrapNamespace('chrome.webRequest');
  wrapNamespace('chrome.history');
  wrapNamespace('chrome.bookmarks');
  wrapNamespace('chrome.identity');
  wrapNamespace('chrome.downloads');

  if (self.chrome && self.chrome.runtime && typeof self.chrome.runtime.sendMessage === 'function') {
    const origSend = self.chrome.runtime.sendMessage.bind(self.chrome.runtime);
    self.chrome.runtime.sendMessage = function() {
      emit({ kind: 'api', api: 'chrome.runtime.sendMessage', args: safeArgs(arguments) });
      return origSend.apply(null, arguments);
    };
  }

  // Network exfiltration paths from the SW
  if (typeof self.fetch === 'function') {
    const origFetch = self.fetch.bind(self);
    self.fetch = function(input, init) {
      let url = '';
      let method = (init && init.method) || 'GET';
      let body;
      try {
        if (typeof input === 'string') url = input;
        else if (input && input.url) { url = input.url; method = input.method || method; }
        if (init && typeof init.body === 'string') body = init.body.substring(0, 5000);
      } catch (e) {}
      emit({ kind: 'fetch', url: url, method: method, body: body });
      return origFetch(input, init);
    };
  }

  if (typeof self.XMLHttpRequest === 'function') {
    const OrigXHR = self.XMLHttpRequest;
    function PatchedXHR() {
      const xhr = new OrigXHR();
      const origOpen = xhr.open.bind(xhr);
      let _method = 'GET'; let _url = '';
      xhr.open = function(method, url) {
        _method = method; _url = url;
        return origOpen.apply(xhr, arguments);
      };
      const origSend = xhr.send.bind(xhr);
      xhr.send = function(body) {
        emit({ kind: 'fetch', url: _url, method: _method, body: typeof body === 'string' ? body.substring(0, 5000) : undefined });
        return origSend.apply(xhr, arguments);
      };
      return xhr;
    }
    self.XMLHttpRequest = PatchedXHR;
  }
})();`;
  }

  // ─── Stealth script builder ───────────────────────────────────────────────

  private buildStealthScript(): string {
    return `(() => {
  // Remove the webdriver flag that sites use to detect headless automation.
  Object.defineProperty(navigator, 'webdriver', { get: () => undefined });

  // Restore chrome runtime object so anti-bot checks see a real browser.
  if (!window.chrome) {
    Object.defineProperty(window, 'chrome', {
      value: { runtime: {}, loadTimes: () => {}, csi: () => {}, app: {} },
      writable: true,
    });
  }

  // Hide HeadlessChrome from the user-agent string exposed to JS.
  const origUA = navigator.userAgent;
  if (origUA.includes('HeadlessChrome')) {
    Object.defineProperty(navigator, 'userAgent', {
      get: () => origUA.replace('HeadlessChrome', 'Chrome'),
    });
  }

  // Spoof a realistic plugin list (real Chrome ships several built-ins).
  Object.defineProperty(navigator, 'plugins', {
    get: () => {
      const plugins = [
        { name: 'Chrome PDF Plugin', filename: 'internal-pdf-viewer' },
        { name: 'Chrome PDF Viewer', filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai' },
        { name: 'Native Client', filename: 'internal-nacl-plugin' },
      ];
      plugins['refresh'] = () => {};
      return plugins;
    },
  });

  // languages — must be non-empty array.
  Object.defineProperty(navigator, 'languages', { get: () => ['es-CO', 'es', 'en-US', 'en'] });

  // Spoof hardware concurrency and device memory to desktop-like values.
  Object.defineProperty(navigator, 'hardwareConcurrency', { get: () => 8 });
  Object.defineProperty(navigator, 'deviceMemory', { get: () => 8 });
})();`;
  }

  // ─── Overlay script builder ───────────────────────────────────────────────

  private buildOverlayScript(extensionId: string): string {
    const safeId = extensionId.substring(0, 20) + '...';
    return `
(function() {
  var _events = [];

  window.__extSandboxAddEvent = function(type, detail, severity) {
    var time = new Date().toLocaleTimeString('es-CO', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    _events.push({ type: type, detail: String(detail), severity: severity || 'info', time: time });
    if (_events.length > 80) _events.shift();
    _render();
  };

  function _color(s) {
    if (s === 'critical') return '#ff3b3b';
    if (s === 'high')     return '#ff8c00';
    if (s === 'medium')   return '#f0d000';
    return '#5b9bd5';
  }

  function _render() {
    var list = document.getElementById('__ess_list');
    if (!list) return;
    var slice = _events.slice(-30).reverse();
    var html = '';
    for (var i = 0; i < slice.length; i++) {
      var e = slice[i];
      var c = _color(e.severity);
      var detail = e.detail.length > 85 ? e.detail.substring(0, 85) + '…' : e.detail;
      html +=
        '<div style="border-bottom:1px solid #0d0d20;padding:3px 0;line-height:1.5;">' +
        '<span style="color:#3a3a5c;font-size:10px;">[' + e.time + '] </span>' +
        '<span style="color:' + c + ';font-weight:bold;">' + e.type + '</span>' +
        '<span style="color:#b0b0c8;"> ' + detail + '</span>' +
        '</div>';
    }
    list.innerHTML = html;
  }

  function _createPanel() {
    if (document.getElementById('__ess_panel')) return;
    if (!document.body) { setTimeout(_createPanel, 50); return; }

    var panel = document.createElement('div');
    panel.id = '__ess_panel';
    panel.style.cssText = [
      'position:fixed', 'top:10px', 'right:10px', 'z-index:2147483647',
      'width:400px', 'max-height:540px',
      'background:rgba(4,4,14,0.97)',
      'color:#c0c0d8', 'font-family:monospace', 'font-size:11px',
      'border:2px solid #cc1111', 'border-radius:8px',
      'padding:12px',
      'box-shadow:0 4px 32px rgba(200,0,0,0.55)',
      'overflow:hidden',
    ].join(';');

    panel.innerHTML =
      '<div style="font-weight:bold;color:#ff3b3b;font-size:13px;' +
        'border-bottom:1px solid #440000;padding-bottom:7px;margin-bottom:7px;">' +
        '🔬 Ext-Sandbox &mdash; Análisis en Vivo' +
      '</div>' +
      '<div style="color:#555;font-size:9px;margin-bottom:6px;">' +
        'Ext: ${safeId}' +
      '</div>' +
      '<div id="__ess_list" style="max-height:400px;overflow-y:auto;"></div>' +
      '<div style="color:#333;font-size:9px;margin-top:7px;border-top:1px solid #0d0d20;padding-top:5px;">' +
        'Monitoreando: red · teclado · DOM · APIs Chrome' +
      '</div>';

    document.body.appendChild(panel);
    _render();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', _createPanel);
  } else {
    setTimeout(_createPanel, 0);
  }

  // ── Intercept fetch ──────────────────────────────────────────────────────
  var _origFetch = window.fetch;
  window.fetch = function() {
    var url = '';
    try {
      var input = arguments[0];
      url = typeof input === 'string' ? input
          : (input instanceof URL ? input.href : (input.url || ''));
    } catch(e) {}
    if (url && !url.startsWith('data:') && !url.startsWith('chrome-extension://') && !url.startsWith('chrome://')) {
      var host = url;
      try { host = new URL(url).hostname; } catch(e) {}
      window.__extSandboxAddEvent('🔴 FETCH', host, 'critical');
    }
    return _origFetch.apply(this, arguments);
  };

  // ── Intercept XHR ────────────────────────────────────────────────────────
  var _OrigXHR = window.XMLHttpRequest;
  window.XMLHttpRequest = function() {
    var xhr = new _OrigXHR();
    var _origOpen = xhr.open.bind(xhr);
    xhr.open = function(method, url) {
      if (url) {
        var host = String(url);
        try { host = new URL(String(url)).hostname; } catch(e) {}
        window.__extSandboxAddEvent('🔴 XHR', method + ' → ' + host, 'critical');
      }
      return _origOpen.apply(xhr, arguments);
    };
    return xhr;
  };

  // ── Monitor keyboard ─────────────────────────────────────────────────────
  document.addEventListener('keydown', function(e) {
    var tgt = e.target;
    var isPass = tgt && tgt.type === 'password';
    var tag = tgt ? '<' + (tgt.tagName || '?') + (isPass ? '[password]' : '') + '>' : '?';
    var key = isPass ? '●' : (e.key || '?');
    window.__extSandboxAddEvent('⌨️ TECLA', key + ' en ' + tag, isPass ? 'critical' : 'high');
  }, true);

  // ── Monitor form submit ──────────────────────────────────────────────────
  document.addEventListener('submit', function(e) {
    var action = (e.target && e.target.action) ? e.target.action : '(sin action)';
    window.__extSandboxAddEvent('📋 FORM SUBMIT', action, 'high');
  }, true);

})();`;
  }
}
