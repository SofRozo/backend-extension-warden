import { Injectable } from '@nestjs/common';
import { StructuredLogger } from '../../common/logger/logger.service.js';
import {
  NetworkRequest,
  DomMutation,
  KeyboardEvent as KbEvent,
  ApiCall,
  DynamicEvidence,
} from '../../common/interfaces/analysis.interfaces.js';

@Injectable()
export class NetworkInterceptorService {
  constructor(private readonly logger: StructuredLogger) {}

  createEvidenceCollector(extensionId: string): EvidenceCollector {
    return new EvidenceCollector(extensionId, this.logger);
  }
}

export class EvidenceCollector {
  private networkRequests: NetworkRequest[] = [];
  private domMutations: DomMutation[] = [];
  private keyboardEvents: KbEvent[] = [];
  private apiCalls: ApiCall[] = [];
  private screenshotPaths: string[] = [];
  private logs: Array<{
    module: string;
    message: string;
    level: string;
    timestamp: number;
  }> = [];
  private extensionOrigin: string;
  private extensionId: string;
  private currentContext: string = 'generic';
  private baselineHosts = new Set<string>();
  private baselineMutations = new Set<string>();

  constructor(
    extensionId: string,
    private readonly logger: StructuredLogger,
  ) {
    this.extensionId = extensionId;
    this.extensionOrigin = `chrome-extension://${extensionId}`;
  }

  onNetworkRequest(
    url: string,
    method: string,
    headers: Record<string, string>,
    body: string | undefined,
    initiator: string | undefined,
    fromServiceWorker: boolean = false,
  ): void {
    if (!isRecordableUrl(url)) {
      return;
    }

    const origin = this.classifyRequestOrigin(
      url,
      initiator,
      fromServiceWorker,
    );

    this.networkRequests.push({
      url,
      method,
      headers,
      body: body ? body.substring(0, 5000) : undefined,
      timestamp: Date.now(),
      origin,
      initiator,
      context: this.currentContext,
    });
  }

  onDomMutation(type: string, target: string, value?: string): void {
    // RNF03: Differential baseline — ignore natural mutations captured during baseline run.
    const mutationKey = `${type}:${target}`;
    if (this.baselineMutations.has(mutationKey)) return;

    this.domMutations.push({
      type,
      target,
      value: value ? value.substring(0, 1000) : undefined,
      timestamp: Date.now(),
      context: this.currentContext,
    });
  }

  onKeyboardEvent(type: string, key?: string, target?: string): void {
    this.keyboardEvents.push({
      type,
      key,
      timestamp: Date.now(),
      target,
      context: this.currentContext,
    });
  }

  onApiCall(api: string, args: string): void {
    this.apiCalls.push({
      api,
      args,
      timestamp: Date.now(),
      context: this.currentContext,
    });
  }

  setContext(context: string): void {
    this.currentContext = context;
  }

  setBaseline(hosts: Set<string>, mutations: Set<string>): void {
    this.baselineHosts = hosts;
    this.baselineMutations = mutations;
  }

  addScreenshot(path: string): void {
    this.screenshotPaths.push(path);
  }

  onLog(module: string, message: string, level: string = 'info'): void {
    this.logs.push({ module, message, level, timestamp: Date.now() });
  }

  getEvidence(): DynamicEvidence {
    return {
      networkRequests: this.networkRequests,
      domMutations: this.domMutations,
      keyboardEvents: this.keyboardEvents,
      apiCalls: this.apiCalls,
      screenshotPaths: this.screenshotPaths,
      logs: this.logs,
    };
  }

  getExtensionRequests(): NetworkRequest[] {
    return this.networkRequests.filter((r) => r.origin === 'extension');
  }

  private classifyRequestOrigin(
    url: string,
    initiator: string | undefined,
    fromServiceWorker: boolean = false,
  ): 'extension' | 'browser' | 'unknown' {
    // Strongest signals: explicit extension URL or initiator
    if (url.startsWith(this.extensionOrigin)) return 'extension';
    if (initiator?.startsWith(this.extensionOrigin)) return 'extension';
    if (url.startsWith('chrome-extension://')) return 'extension';
    if (initiator?.startsWith('chrome-extension://')) return 'extension';

    // Service worker fetches from this extension's SW
    if (fromServiceWorker) return 'extension';

    // Chrome internal URLs
    if (
      url.startsWith('chrome://') ||
      url.startsWith('chrome-search://') ||
      url.startsWith('chrome-untrusted://') ||
      url.startsWith('devtools://') ||
      url.includes('clients2.google.com') ||
      url.includes('update.googleapis.com') ||
      url.includes('safebrowsing.googleapis.com') ||
      url.includes('optimizationguide-pa.googleapis.com')
    ) {
      return 'browser';
    }

    // Requests to hosts seen in a clean-browser baseline are natural page traffic,
    // not extension activity — reclassify to avoid false positives.
    try {
      const hostname = new URL(url).hostname;
      if (hostname && this.baselineHosts.has(hostname)) return 'browser';
    } catch {
      /* ignore malformed URLs */
    }

    return 'unknown';
  }
}

/**
 * Filter out non-network noise: chrome internals, data/blob URIs, and malformed
 * URLs that look like asset filenames being misinterpreted as hosts (e.g.
 * "https://main.js/", "https://breedspritecache.js/").
 */
export function isRecordableUrl(url: string): boolean {
  if (!url || typeof url !== 'string') return false;

  // Skip non-HTTP schemes that aren't real network traffic
  if (
    url.startsWith('data:') ||
    url.startsWith('blob:') ||
    url.startsWith('javascript:') ||
    url.startsWith('about:') ||
    url.startsWith('file:')
  ) {
    return false;
  }

  // Always record extension and chrome scheme requests for classification
  if (
    url.startsWith('chrome-extension://') ||
    url.startsWith('chrome://') ||
    url.startsWith('chrome-search://') ||
    url.startsWith('devtools://')
  ) {
    return true;
  }

  // For http(s), require a hostname with at least one dot and a non-asset TLD
  if (!/^https?:\/\//i.test(url)) return false;

  let hostname: string;
  try {
    hostname = new URL(url).hostname.toLowerCase();
  } catch {
    return false;
  }

  if (!hostname) return false;

  // Reject hostnames that are clearly file names misclassified as hosts
  const ASSET_EXT =
    /\.(js|mjs|css|png|jpe?g|gif|svg|webp|ico|woff2?|ttf|otf|map|json|xml|html?)$/i;
  if (ASSET_EXT.test(hostname)) return false;

  // Allow localhost and IPs
  if (hostname === 'localhost' || /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname))
    return true;

  // Real hostnames have at least one dot and a TLD of 2+ chars
  if (!hostname.includes('.')) return false;
  const tld = hostname.split('.').pop() ?? '';
  if (tld.length < 2 || /^\d+$/.test(tld)) return false;

  return true;
}
