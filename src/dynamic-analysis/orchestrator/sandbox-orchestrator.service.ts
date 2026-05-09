import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as fs from 'fs';
import * as path from 'path';
import { StructuredLogger } from '../../common/logger/logger.service.js';
import {
  NetworkInterceptorService,
  EvidenceCollector,
} from '../network-interceptor/network-interceptor.service.js';
import { IntelligentNavigatorService } from '../navigator/intelligent-navigator.service.js';
import { StagehandService } from '../navigator/stagehand.service.js';
import {
  DomainFinding,
  DynamicAnalysisResult,
  SandboxDomainObservation,
} from '../../common/interfaces/analysis.interfaces.js';
import { DetonationStrategy } from '../../common/enums/risk-level.enum.js';

/**
 * Drives the dynamic phase. Loads the extension into a Playwright instance
 * and, for each priority domain found in resultado2_priority, asks the
 * navigator (Stagehand or IntelligentNavigator) to interact with the page
 * while we monitor network/DOM/key/API events.
 */
@Injectable()
export class SandboxOrchestratorService {
  constructor(
    private readonly config: ConfigService,
    private readonly logger: StructuredLogger,
    private readonly networkInterceptor: NetworkInterceptorService,
    private readonly intelligentNavigator: IntelligentNavigatorService,
    private readonly stagehand: StagehandService,
  ) {}

  async executeDynamicAnalysis(
    extensionPath: string,
    extensionId: string,
    priorityFindings: DomainFinding[],
    proposito: string,
    jobId: string,
  ): Promise<DynamicAnalysisResult> {
    const timeoutMs =
      this.config.get<number>('analysis.dynamicTimeoutMs') || 180000;
    const demoMode = this.config.get<boolean>('demo.enabled') || false;
    const demoSlowMo = this.config.get<number>('demo.slowMo') || 800;
    const useStagehand =
      this.config.get<boolean>('analysis.useStagehand') || false;
    const startTime = Date.now();

    this.logger.logWithJob(
      jobId,
      'info',
      `Starting dynamic analysis${demoMode ? ' [DEMO MODE — headed browser]' : ''}`,
      'SandboxOrchestrator',
    );

    // Resolve unique domains (priority findings can repeat the same host).
    const targets = this.uniqueTargets(priorityFindings);
    this.logger.logWithJob(
      jobId,
      'info',
      `Visiting ${targets.length} priority domain(s)`,
      'SandboxOrchestrator',
    );

    const collector =
      this.networkInterceptor.createEvidenceCollector(extensionId);
    const domainObservations: SandboxDomainObservation[] = [];
    let timedOut = false;

    if (targets.length === 0) {
      return {
        strategy: DetonationStrategy.DIRECT_NAVIGATION,
        evidence: collector.getEvidence(),
        duration: Date.now() - startTime,
        timedOut: false,
        domainObservations: [],
      };
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
      if (!demoMode) browserArgs.push('--headless=new');

      const browser = await chromium.launchPersistentContext('', {
        headless: demoMode ? false : true,
        slowMo: demoMode ? demoSlowMo : 0,
        args: browserArgs,
        timeout: 30000,
        userAgent:
          'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ' +
          '(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
        viewport: { width: 1920, height: 1080 },
        locale: 'es-CO',
        timezoneId: 'America/Bogota',
      });

      await browser.addInitScript(this.buildStealthScript()).catch(() => {});

      this.instrumentExtensionServiceWorker(
        browser,
        extensionId,
        collector,
        jobId,
      );

      try {
        for (const target of targets) {
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

          const obs = await this.visitDomain(
            browser,
            target,
            proposito,
            useStagehand,
            collector,
            extensionId,
            jobId,
          );
          domainObservations.push(obs);
        }
      } finally {
        await browser.close().catch(() => {});
      }
    } catch (err) {
      this.logger.logWithJob(
        jobId,
        'error',
        `Dynamic analysis error: ${err instanceof Error ? err.message : String(err)}`,
        'SandboxOrchestrator',
      );
    }

    return {
      strategy: DetonationStrategy.DIRECT_NAVIGATION,
      evidence: collector.getEvidence(),
      duration: Date.now() - startTime,
      timedOut,
      domainObservations,
    };
  }

  // ─── Per-domain navigation ────────────────────────────────────────────────

  private async visitDomain(
    browser: any,
    target: { domain: string; category: string },
    proposito: string,
    useStagehand: boolean,
    collector: EvidenceCollector,
    extensionId: string,
    jobId: string,
  ): Promise<SandboxDomainObservation> {
    const page = await browser.newPage();
    this.setupPageInterception(page, collector);
    await this.setupScreenshots(page, jobId, target.domain, collector);
    await this.setupApiInterception(page, extensionId);

    collector.setContext('DIRECT_NAVIGATION');

    try {
      let observation: SandboxDomainObservation;
      if (useStagehand) {
        observation = await this.stagehand.navigateDomain(
          page,
          browser,
          target.domain,
          target.category as any,
          proposito,
          jobId,
        );
      } else {
        observation = await this.intelligentNavigator.navigateDomain(
          page,
          browser,
          target.domain,
          target.category as any,
          proposito,
          jobId,
        );
      }

      for (const obs of observation.observations ?? []) {
        collector.onLog('Navigator', obs, 'info');
      }

      await this.takePageScreenshot(page, 'final', collector);
      await this.collectPageEvidence(page, collector);
      return observation;
    } catch (err) {
      const msg = `Visit ${target.domain} failed: ${err instanceof Error ? err.message : String(err)}`;
      this.logger.logWithJob(jobId, 'warn', msg, 'SandboxOrchestrator');
      return {
        domain: target.domain,
        url: `https://${target.domain}`,
        observations: [msg],
        actionsPerformed: [],
        requestsToThisDomain: 0,
        domModificationsDetected: false,
        credentialsSubmitted: false,
        honeypotSessionUsed: false,
        error: err instanceof Error ? err.message : String(err),
      };
    } finally {
      await page.close().catch(() => {});
    }
  }

  // ─── Helpers ───────────────────────────────────────────────────────────────

  private uniqueTargets(
    priorityFindings: DomainFinding[],
  ): Array<{ domain: string; category: string }> {
    const seen = new Map<string, { domain: string; category: string }>();
    const sorted = [...priorityFindings].sort(
      (a, b) => (a.priority ?? 99) - (b.priority ?? 99),
    );
    for (const f of sorted) {
      const key = f.domain.toLowerCase();
      if (!seen.has(key)) seen.set(key, { domain: f.domain, category: f.category });
    }
    // Cap at 5 domains so the dynamic phase respects its budget.
    return [...seen.values()].slice(0, 5);
  }

  // ─── Page setup helpers ───────────────────────────────────────────────────

  private async setupScreenshots(
    page: any,
    jobId: string,
    label: string,
    collector: EvidenceCollector,
  ): Promise<void> {
    const baseDir =
      this.config.get<string>('analysis.screenshotsDir') ||
      '/tmp/ext-sandbox/screenshots';
    const dir = path.join(baseDir, jobId);
    fs.mkdirSync(dir, { recursive: true });
    try {
      fs.chmodSync(dir, 0o777);
    } catch {
      /* ignore on Windows */
    }
    let idx = 0;
    page.__screenshotDir = dir;
    page.__screenshotLabel = label;
    page.__screenshotIndex = () => idx++;

    await page.exposeFunction(
      '__extSandboxCriticalMutation',
      async (reason: string) => {
        const filePath = path.join(dir, `${label}_critical_${idx++}_${reason}.png`);
        try {
          await page.screenshot({ path: filePath, fullPage: false });
          try {
            fs.chmodSync(filePath, 0o666);
          } catch {
            /* ignore */
          }
          collector.addScreenshot(filePath);
        } catch {
          /* page might have navigated */
        }
      },
    );
  }

  private async takePageScreenshot(
    page: any,
    suffix: string,
    collector: EvidenceCollector,
  ): Promise<void> {
    const dir: string = page.__screenshotDir;
    const label: string = page.__screenshotLabel ?? 'page';
    const getIndex: () => number = page.__screenshotIndex ?? (() => 0);
    if (!dir) return;
    const filePath = path.join(dir, `${label}_${getIndex()}_${suffix}.png`);
    try {
      await page.screenshot({ path: filePath, fullPage: false });
      try {
        fs.chmodSync(filePath, 0o666);
      } catch {
        /* ignore */
      }
      collector.addScreenshot(filePath);
    } catch {
      /* best effort */
    }
  }

  private async setupApiInterception(page: any, extensionId: string): Promise<void> {
    void extensionId;
    await page.addInitScript(() => {
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
      };

      const origFetch = window.fetch.bind(window);
      window.fetch = (input: RequestInfo | URL, init?: RequestInit) => {
        const url =
          typeof input === 'string'
            ? input
            : input instanceof URL
              ? input.href
              : input.url;
        record('fetch', [
          url,
          {
            method: init?.method,
            bodyPreview: String(init?.body ?? '').substring(0, 500),
          },
        ]);
        return origFetch(input, init);
      };

      const OrigXHR = window.XMLHttpRequest;
      (window as any).XMLHttpRequest = class extends OrigXHR {
        open(method: string, url: string) {
          record('XMLHttpRequest.open', [method, url]);
          return super.open(method, url);
        }
      };
    });
  }

  private setupPageInterception(
    page: any,
    collector: EvidenceCollector,
  ): void {
    page.on('request', (request: any) => {
      try {
        const url: string = request.url();
        const method: string = request.method();
        const headers: Record<string, string> = request.headers();
        const body: string | undefined = request.postData();
        const initiator: string | undefined = request.frame()?.url();
        collector.onNetworkRequest(url, method, headers, body, initiator);
      } catch {
        /* best effort */
      }
    });
  }

  private async collectPageEvidence(
    page: any,
    collector: EvidenceCollector,
  ): Promise<void> {
    try {
      const apiCalls: any[] = await page.evaluate(
        () => (window as any).__extSandboxApiCalls || [],
      );
      for (const call of apiCalls) {
        collector.onApiCall(call.api, call.args);
      }
    } catch {
      /* page may have navigated */
    }
  }

  // ─── Service worker instrumentation ───────────────────────────────────────

  private instrumentExtensionServiceWorker(
    browser: any,
    extensionId: string,
    collector: EvidenceCollector,
    jobId: string,
  ): void {
    const swUrlPrefix = `chrome-extension://${extensionId}/`;

    browser.on('serviceworker', (sw: any) => {
      const url = typeof sw.url === 'function' ? sw.url() : sw.url;
      if (typeof url === 'string' && url.startsWith(swUrlPrefix)) {
        this.attachToServiceWorker(sw, collector, jobId).catch(() => {});
      }
    });

    try {
      const existing: any[] = browser.serviceWorkers?.() ?? [];
      for (const sw of existing) {
        const url = typeof sw.url === 'function' ? sw.url() : sw.url;
        if (typeof url === 'string' && url.startsWith(swUrlPrefix)) {
          this.attachToServiceWorker(sw, collector, jobId).catch(() => {});
        }
      }
    } catch {
      /* older Playwright */
    }
  }

  private async attachToServiceWorker(
    sw: any,
    collector: EvidenceCollector,
    jobId: string,
  ): Promise<void> {
    const swUrl: string = typeof sw.url === 'function' ? sw.url() : sw.url;
    this.logger.logWithJob(
      jobId,
      'info',
      `Instrumenting extension service worker: ${swUrl}`,
      'SandboxOrchestrator',
    );

    sw.on?.('console', (msg: any) => {
      try {
        const text: string =
          typeof msg.text === 'function' ? msg.text() : String(msg);
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
        /* ignore */
      }
    });

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
  }

  private buildServiceWorkerWrapper(): string {
    return `(() => {
  if (self.__extSandboxInstrumented) return;
  self.__extSandboxInstrumented = true;
  function emit(payload) { try { console.log('[SANDBOX_API] ' + JSON.stringify(payload)); } catch (e) {} }
  function safeArgs(args) { try { return JSON.stringify(Array.from(args)).substring(0, 2000); } catch (e) { return '[unserializable]'; } }
  function wrapNamespace(nsPath) {
    const parts = nsPath.split('.');
    let obj = self;
    for (const p of parts) { if (!obj || typeof obj[p] === 'undefined') return; obj = obj[p]; }
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
  wrapNamespace('chrome.storage.local');
  wrapNamespace('chrome.storage.sync');
  wrapNamespace('chrome.cookies');
  wrapNamespace('chrome.tabs');
  wrapNamespace('chrome.scripting');
  wrapNamespace('chrome.webRequest');
  wrapNamespace('chrome.history');
  wrapNamespace('chrome.bookmarks');
  wrapNamespace('chrome.identity');
  wrapNamespace('chrome.downloads');
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
})();`;
  }

  private buildStealthScript(): string {
    return `(() => {
  Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
  if (!window.chrome) {
    Object.defineProperty(window, 'chrome', { value: { runtime: {}, loadTimes: () => {}, csi: () => {}, app: {} }, writable: true });
  }
  const origUA = navigator.userAgent;
  if (origUA.includes('HeadlessChrome')) {
    Object.defineProperty(navigator, 'userAgent', { get: () => origUA.replace('HeadlessChrome', 'Chrome') });
  }
  Object.defineProperty(navigator, 'plugins', {
    get: () => {
      const plugins = [
        { name: 'Chrome PDF Plugin', filename: 'internal-pdf-viewer' },
        { name: 'Chrome PDF Viewer', filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai' },
      ];
      plugins['refresh'] = () => {};
      return plugins;
    },
  });
  Object.defineProperty(navigator, 'languages', { get: () => ['es-CO', 'es', 'en-US', 'en'] });
  Object.defineProperty(navigator, 'hardwareConcurrency', { get: () => 8 });
  Object.defineProperty(navigator, 'deviceMemory', { get: () => 8 });
})();`;
  }
}
