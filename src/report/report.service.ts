import { Injectable } from '@nestjs/common';
import { StructuredLogger } from '../common/logger/logger.service.js';
import {
  StaticAnalysisResult,
  DynamicAnalysisResult,
  ThreatIntelResult,
  AnalysisReport,
  AnnotatedPermission,
  PrivacyLabel,
  StaticFinding,
  ContactedUrlReputation,
  AgentAnalysisResult,
} from '../common/interfaces/analysis.interfaces.js';
import { RiskLevel, FindingCategory } from '../common/enums/risk-level.enum.js';

interface PermissionMeta {
  description: string;
  category: string;
  risk: RiskLevel;
}

// Risk classification mirrors ExtWarden/src/data/permissionWeights.ts (tesis taxonomy).
const CHROME_PERMISSION_DESCRIPTIONS: Record<string, PermissionMeta> = {
  // ── CRITICAL ──────────────────────────────────────────────────────────────
  tabCapture: {
    description: 'Capture the visible content of any browser tab',
    category: 'Screen Capture',
    risk: RiskLevel.CRITICAL,
  },
  pageCapture: {
    description: 'Save complete web pages as MHTML — full content snapshot',
    category: 'Screen Capture',
    risk: RiskLevel.CRITICAL,
  },
  debugger: {
    description: 'Attach a debugger — grants full control over any tab',
    category: 'System',
    risk: RiskLevel.CRITICAL,
  },
  nativeMessaging: {
    description: 'Communicate with native applications installed on the OS',
    category: 'System',
    risk: RiskLevel.CRITICAL,
  },
  proxy: {
    description: 'Control all browser proxy settings — intercepts all traffic',
    category: 'Network',
    risk: RiskLevel.CRITICAL,
  },
  vpnProvider: {
    description: 'Implement a VPN client that routes all browser traffic',
    category: 'Network',
    risk: RiskLevel.CRITICAL,
  },
  '<all_urls>': {
    description: 'Access all websites without restriction',
    category: 'Host Access',
    risk: RiskLevel.CRITICAL,
  },

  // ── HIGH ──────────────────────────────────────────────────────────────────
  cookies: {
    description: 'Read and write cookies for any website visited',
    category: 'Data Access',
    risk: RiskLevel.HIGH,
  },
  scripting: {
    description: 'Inject JavaScript and CSS into web pages',
    category: 'Content Injection',
    risk: RiskLevel.HIGH,
  },
  declarativeNetRequest: {
    description: 'Block or redirect network requests via declarative rules',
    category: 'Network',
    risk: RiskLevel.HIGH,
  },
  declarativeNetRequestWithHostAccess: {
    description: 'Block or redirect network requests across all hosts',
    category: 'Network',
    risk: RiskLevel.HIGH,
  },
  webRequest: {
    description: 'Observe and intercept all network requests',
    category: 'Network',
    risk: RiskLevel.HIGH,
  },
  webRequestBlocking: {
    description: 'Block and modify network requests in real time',
    category: 'Network',
    risk: RiskLevel.HIGH,
  },
  userScripts: {
    description: 'Execute arbitrary user scripts in page context',
    category: 'Content Injection',
    risk: RiskLevel.HIGH,
  },
  desktopCapture: {
    description: 'Capture the screen, window, or tab contents',
    category: 'Screen Capture',
    risk: RiskLevel.HIGH,
  },
  history: {
    description: 'Read and modify full browser history',
    category: 'Data Access',
    risk: RiskLevel.HIGH,
  },
  downloads: {
    description: 'Manage file downloads and access downloaded files',
    category: 'Files',
    risk: RiskLevel.HIGH,
  },
  'downloads.open': {
    description: "Open downloaded files on the user's device",
    category: 'Files',
    risk: RiskLevel.HIGH,
  },
  privacy: {
    description: 'Query and modify privacy-related browser settings',
    category: 'System',
    risk: RiskLevel.HIGH,
  },
  browsingData: {
    description: 'Clear browsing data — cookies, cache, and history',
    category: 'Data Access',
    risk: RiskLevel.HIGH,
  },
  contentSettings: {
    description: 'Change per-site content settings (camera, mic, geolocation)',
    category: 'System',
    risk: RiskLevel.HIGH,
  },
  webNavigation: {
    description: 'Observe navigation events across all tabs',
    category: 'Navigation',
    risk: RiskLevel.HIGH,
  },
  webAuthenticationProxy: {
    description: 'Act as a proxy for Web Authentication requests',
    category: 'Authentication',
    risk: RiskLevel.HIGH,
  },
  certificateProvider: {
    description: 'Provide TLS client certificates to the browser',
    category: 'Authentication',
    risk: RiskLevel.HIGH,
  },
  platformKeys: {
    description: 'Access platform and user certificate stores',
    category: 'Authentication',
    risk: RiskLevel.HIGH,
  },

  // ── MEDIUM ────────────────────────────────────────────────────────────────
  tabs: {
    description: 'Access URLs, titles, and favicons of open tabs',
    category: 'Navigation',
    risk: RiskLevel.MEDIUM,
  },
  activeTab: {
    description: 'Access the currently active tab on user action',
    category: 'Navigation',
    risk: RiskLevel.MEDIUM,
  },
  alarms: {
    description: 'Schedule code to run at set times or intervals',
    category: 'Background',
    risk: RiskLevel.MEDIUM,
  },
  bookmarks: {
    description: 'Read and modify browser bookmarks',
    category: 'Data Access',
    risk: RiskLevel.MEDIUM,
  },
  clipboardRead: {
    description: 'Read the contents of the clipboard',
    category: 'Data Access',
    risk: RiskLevel.MEDIUM,
  },
  clipboardWrite: {
    description: 'Write arbitrary content to the clipboard',
    category: 'Data Access',
    risk: RiskLevel.MEDIUM,
  },
  geolocation: {
    description: "Access the device's geographic location",
    category: 'Data Access',
    risk: RiskLevel.MEDIUM,
  },
  identity: {
    description: 'Obtain OAuth2 tokens and user identity information',
    category: 'Authentication',
    risk: RiskLevel.MEDIUM,
  },
  'identity.email': {
    description: "Access the user's email address via OAuth2",
    category: 'Authentication',
    risk: RiskLevel.MEDIUM,
  },
  management: {
    description: 'List, enable, disable, or uninstall other extensions',
    category: 'System',
    risk: RiskLevel.MEDIUM,
  },
  sessions: {
    description: 'Access recently closed tabs and windows',
    category: 'Data Access',
    risk: RiskLevel.MEDIUM,
  },
  topSites: {
    description: "Retrieve the user's most frequently visited sites",
    category: 'Data Access',
    risk: RiskLevel.MEDIUM,
  },
  contextMenus: {
    description: 'Add items to the browser right-click context menu',
    category: 'UI',
    risk: RiskLevel.MEDIUM,
  },
  tabGroups: {
    description: 'Create and manage tab groups',
    category: 'Navigation',
    risk: RiskLevel.MEDIUM,
  },
  dns: {
    description: 'Resolve hostnames via the browser DNS API',
    category: 'Network',
    risk: RiskLevel.MEDIUM,
  },
  offscreen: {
    description: 'Create off-screen documents for background processing',
    category: 'Background',
    risk: RiskLevel.MEDIUM,
  },
  processes: {
    description: 'Query and observe renderer process information',
    category: 'System',
    risk: RiskLevel.MEDIUM,
  },

  // ── LOW ───────────────────────────────────────────────────────────────────
  storage: {
    description: 'Store and retrieve extension data (synced or local)',
    category: 'Storage',
    risk: RiskLevel.LOW,
  },
  unlimitedStorage: {
    description: 'Use unlimited quota in Chrome storage APIs',
    category: 'Storage',
    risk: RiskLevel.LOW,
  },
  notifications: {
    description: 'Display desktop notifications to the user',
    category: 'UI',
    risk: RiskLevel.LOW,
  },
  idle: {
    description: 'Detect whether the machine is idle, locked, or active',
    category: 'System',
    risk: RiskLevel.LOW,
  },
  power: {
    description: 'Prevent the system from entering sleep mode',
    category: 'System',
    risk: RiskLevel.LOW,
  },
  tts: {
    description: 'Synthesize text-to-speech audio output',
    category: 'UI',
    risk: RiskLevel.LOW,
  },
  ttsEngine: {
    description: 'Implement a custom text-to-speech engine',
    category: 'UI',
    risk: RiskLevel.LOW,
  },
  fontSettings: {
    description: 'Read and modify browser font settings',
    category: 'System',
    risk: RiskLevel.LOW,
  },
  declarativeContent: {
    description: 'Conditionally show or hide the extension icon',
    category: 'UI',
    risk: RiskLevel.LOW,
  },
  gcm: {
    description: 'Send and receive messages via Google Cloud Messaging',
    category: 'Background',
    risk: RiskLevel.LOW,
  },
  sidePanel: {
    description: 'Display content in the browser side panel',
    category: 'UI',
    risk: RiskLevel.LOW,
  },
  search: {
    description: 'Use the default search provider programmatically',
    category: 'Navigation',
    risk: RiskLevel.LOW,
  },
  favicon: {
    description: 'Fetch favicons for arbitrary URLs',
    category: 'Navigation',
    risk: RiskLevel.LOW,
  },
  readingList: {
    description: 'Add, remove, and query the browser reading list',
    category: 'Data Access',
    risk: RiskLevel.LOW,
  },
  printing: {
    description: 'Send content to the system print dialog',
    category: 'System',
    risk: RiskLevel.LOW,
  },
  printingMetrics: {
    description: 'Access print job history metrics',
    category: 'System',
    risk: RiskLevel.LOW,
  },
  documentScan: {
    description: 'Access document scanner devices',
    category: 'System',
    risk: RiskLevel.LOW,
  },
  loginState: {
    description: 'Query the sign-in state of the browser profile',
    category: 'Authentication',
    risk: RiskLevel.LOW,
  },
  background: {
    description: 'Run the extension even when Chrome is not open',
    category: 'Background',
    risk: RiskLevel.LOW,
  },
  declarativeNetRequestFeedback: {
    description: 'Read matched declarative network rule information',
    category: 'Network',
    risk: RiskLevel.LOW,
  },
  'downloads.ui': {
    description: 'Remove items from the downloads UI',
    category: 'Files',
    risk: RiskLevel.LOW,
  },
  'system.cpu': {
    description: 'Query CPU metadata',
    category: 'System',
    risk: RiskLevel.LOW,
  },
  'system.display': {
    description: 'Query and configure display settings',
    category: 'System',
    risk: RiskLevel.LOW,
  },
  'system.memory': {
    description: 'Query physical memory capacity',
    category: 'System',
    risk: RiskLevel.LOW,
  },
  'system.storage': {
    description: 'Query storage device information',
    category: 'System',
    risk: RiskLevel.LOW,
  },
  printerProvider: {
    description: 'Implement a network print provider',
    category: 'System',
    risk: RiskLevel.LOW,
  },
  'accessibilityFeatures.modify': {
    description: 'Modify accessibility feature settings',
    category: 'System',
    risk: RiskLevel.LOW,
  },
  'accessibilityFeatures.read': {
    description: 'Read current accessibility feature settings',
    category: 'System',
    risk: RiskLevel.LOW,
  },
};

const SEVERITY_ORDER: Record<RiskLevel, number> = {
  [RiskLevel.CRITICAL]: 5,
  [RiskLevel.HIGH]: 4,
  [RiskLevel.MEDIUM]: 3,
  [RiskLevel.LOW]: 2,
  [RiskLevel.INFORMATIONAL]: 1,
  [RiskLevel.NONE]: 0,
};

const CATEGORY_LABELS: Record<
  FindingCategory,
  { title: string; userFriendly: string }
> = {
  [FindingCategory.DATA_THEFT]: {
    title: 'Data Access',
    userFriendly:
      'This extension can read your personal data including passwords and form inputs.',
  },
  [FindingCategory.KEYLOGGER]: {
    title: 'Keystroke Monitoring',
    userFriendly:
      'This extension monitors your keyboard activity and may record what you type.',
  },
  [FindingCategory.INJECTION]: {
    title: 'Content Injection',
    userFriendly:
      'This extension can modify web pages and inject its own content into sites you visit.',
  },
  [FindingCategory.EXFILTRATION]: {
    title: 'Data Transmission',
    userFriendly: 'This extension sends data to external servers.',
  },
  [FindingCategory.DOMAIN_TARGETING]: {
    title: 'Targeted Sites',
    userFriendly: 'This extension specifically targets certain websites.',
  },
  [FindingCategory.PERSISTENCE]: {
    title: 'Background Activity',
    userFriendly:
      'This extension runs processes in the background even when you are not actively using it.',
  },
};

@Injectable()
export class ReportService {
  constructor(private readonly logger: StructuredLogger) {}

  generateReport(
    jobId: string,
    extensionId: string,
    staticResult: StaticAnalysisResult,
    dynamicResult: DynamicAnalysisResult | null,
    threatIntelResults: ThreatIntelResult[],
    analysisDuration: number,
    metadata?: { name?: string; version?: string; author?: string },
    agentAnalysis?: AgentAnalysisResult,
  ): AnalysisReport {
    const privacyLabels = this.generatePrivacyLabels(
      staticResult,
      dynamicResult,
      threatIntelResults,
    );

    const overallRisk = this.calculateOverallRisk(
      staticResult,
      dynamicResult,
      threatIntelResults,
    );

    const contactedUrls = this.extractContactedUrls(dynamicResult);
    const contactedUrlsReputation = this.buildUrlReputation(
      contactedUrls,
      threatIntelResults,
    );
    const abusedPermissions = this.detectAbusedPermissions(staticResult);
    const annotatedPermissions = this.annotatePermissions(
      staticResult.manifestPermissions,
      abusedPermissions,
    );
    const score1 = this.calculateScore1(staticResult.manifestPermissions);
    const score2 = this.calculateScore2(score1, agentAnalysis);
    const score3 = this.calculateScore3(score2, dynamicResult, agentAnalysis);

    const recommendation = this.generateRecommendation(overallRisk);
    const confidence = this.calculateConfidence(staticResult, dynamicResult);
    const testResults = this.generateTestResults(dynamicResult);

    return {
      jobId,
      extensionId,
      extensionName: metadata?.name || undefined,
      extensionVersion: metadata?.version || undefined,
      extensionAuthor: metadata?.author || undefined,
      crxHash: staticResult.crxHash,
      overallRisk,
      score1,
      score2,
      score3,
      privacyLabels,
      staticFindings: staticResult.findings,
      dynamicEvidence: dynamicResult?.evidence,
      threatIntelResults,
      contactedUrls: this.deduplicateUrls(
        contactedUrls,
        contactedUrlsReputation,
      ),
      contactedUrlsReputation,
      abusedPermissions,
      annotatedPermissions,
      recommendation,
      analysisTimestamp: new Date(),
      analysisDuration,
      confidence,
      agentAnalysis,
      testResults,
    };
  }

  private annotatePermissions(
    permissions: string[],
    abusedPermissions: string[],
  ): AnnotatedPermission[] {
    const abusedSet = new Set(abusedPermissions);
    return permissions.map((name) => {
      const meta: PermissionMeta = CHROME_PERMISSION_DESCRIPTIONS[name] ?? {
        description: `Chrome extension permission: ${name}`,
        category: 'Other',
        risk: RiskLevel.LOW,
      };
      return {
        name,
        description: meta.description,
        category: meta.category,
        risk: meta.risk,
        isAbused: abusedSet.has(name),
      };
    });
  }

  private deduplicateUrls(
    directUrls: string[],
    reputations: ContactedUrlReputation[],
  ): string[] {
    const allUrls = [...directUrls, ...reputations.map((r) => r.url)];
    return [...new Set(allUrls)];
  }

  private generatePrivacyLabels(
    staticResult: StaticAnalysisResult,
    dynamicResult: DynamicAnalysisResult | null,
    threatIntelResults: ThreatIntelResult[],
  ): PrivacyLabel[] {
    const labels: PrivacyLabel[] = [];

    // Group static findings by category
    const findingsByCategory = new Map<FindingCategory, StaticFinding[]>();
    for (const finding of staticResult.findings) {
      const list = findingsByCategory.get(finding.category) || [];
      list.push(finding);
      findingsByCategory.set(finding.category, list);
    }

    for (const [category, findings] of findingsByCategory) {
      const label = CATEGORY_LABELS[category];
      if (!label) continue;

      const maxSeverity = findings.reduce(
        (max, f) =>
          SEVERITY_ORDER[f.severity] > SEVERITY_ORDER[max] ? f.severity : max,
        RiskLevel.NONE,
      );

      // Skip labels that only have noise-level findings (e.g. keyboard listener in popup)
      if (
        SEVERITY_ORDER[maxSeverity] <= SEVERITY_ORDER[RiskLevel.INFORMATIONAL]
      )
        continue;

      labels.push({
        category: category,
        title: label.title,
        description: label.userFriendly,
        severity: maxSeverity,
        evidence: findings.map(
          (f) => `${f.description} (${f.location.file}:${f.location.line})`,
        ),
      });
    }

    // Add domain targeting label
    const restrictedDomains = staticResult.discoveredDomains.filter(
      (d) => d.platformLevel === 3,
    );
    if (restrictedDomains.length > 0) {
      labels.push({
        category: FindingCategory.DOMAIN_TARGETING,
        title: 'Sensitive Site Targeting',
        description: `This extension contains hardcoded references to ${restrictedDomains.length} sensitive platform(s) including banking, educational, or government sites.`,
        severity: RiskLevel.CRITICAL,
        evidence: restrictedDomains.map(
          (d) => `Targets ${d.domain} (${d.category}) found in ${d.source}`,
        ),
      });
    }

    // Add threat intel label
    const maliciousDomains = threatIntelResults.filter((t) => t.isMalicious);
    if (maliciousDomains.length > 0) {
      labels.push({
        category: 'threat_intelligence',
        title: 'Known Malicious Infrastructure',
        description: `This extension communicates with ${maliciousDomains.length} domain(s) flagged as malicious by threat intelligence providers.`,
        severity: RiskLevel.CRITICAL,
        evidence: maliciousDomains.map(
          (d) =>
            `${d.domain} flagged by ${d.provider} (score: ${d.score?.toFixed(2)})`,
        ),
      });
    }

    // Add dynamic evidence label
    if (dynamicResult) {
      const extRequests = dynamicResult.evidence.networkRequests.filter(
        (r) =>
          (r.origin === 'extension' || r.origin === 'unknown') &&
          r.url.startsWith('http'),
      );
      if (extRequests.length > 0) {
        labels.push({
          category: 'dynamic_network',
          title: 'Network Activity Detected',
          description: `During dynamic analysis, the extension made ${extRequests.length} network request(s) to external servers.`,
          severity: extRequests.length > 5 ? RiskLevel.HIGH : RiskLevel.MEDIUM,
          evidence: extRequests
            .slice(0, 10)
            .map((r) => `[${r.context || 'generic'}] ${r.method} ${r.url}`),
        });
      }

      // Exclude passive_trigger mutations — those are the observed page's own resources
      // loading (Google, Wikipedia), not modifications made by the extension.
      const activeMutations = dynamicResult.evidence.domMutations.filter(
        (m) =>
          m.context !== 'passive_trigger' && m.context !== 'PASSIVE_TRIGGER',
      );
      if (activeMutations.length > 0) {
        labels.push({
          category: 'dynamic_dom',
          title: 'Page Modification Detected',
          description:
            'The extension modified web page content during dynamic analysis.',
          severity: RiskLevel.MEDIUM,
          evidence: activeMutations
            .slice(0, 5)
            .map(
              (m) =>
                `[${m.context || 'generic'}] ${m.type} mutation on ${m.target}`,
            ),
        });
      }

      // ── Keyboard activity (potential keylogger evidence) ──────────────────
      const keyEvents = dynamicResult.evidence.keyboardEvents ?? [];
      if (keyEvents.length > 0) {
        const passwordHits = keyEvents.filter((k) =>
          /password/i.test(k.target ?? ''),
        );
        const severity =
          passwordHits.length > 0 ? RiskLevel.CRITICAL : RiskLevel.MEDIUM;
        const title =
          passwordHits.length > 0
            ? 'Vigila lo que escribes en contraseñas'
            : 'Monitorea tu teclado';
        const evidence = (passwordHits.length > 0 ? passwordHits : keyEvents)
          .slice(0, 8)
          .map(
            (k) =>
              `[${k.context || 'generic'}] ${k.type} en ${k.target ?? '?'}`,
          );

        labels.push({
          category: 'dynamic_keyboard',
          title,
          description:
            passwordHits.length > 0
              ? `Se detectaron ${passwordHits.length} pulsaciones sobre campos de contraseña durante el análisis dinámico.`
              : `Se capturaron ${keyEvents.length} eventos de teclado durante el análisis dinámico.`,
          severity,
          evidence,
        });
      }

      // ── Chrome API surface abuse (from SW instrumentation) ────────────────
      // Filter to chrome.* only — the SW intercept also captures XMLHttpRequest.open
      // and fetch() calls from web pages, which are not extension API usage.
      const chromeCalls = (dynamicResult.evidence.apiCalls ?? []).filter((c) =>
        c.api.startsWith('chrome.'),
      );
      if (chromeCalls.length > 0) {
        const counts = new Map<string, number>();
        for (const c of chromeCalls) {
          counts.set(c.api, (counts.get(c.api) ?? 0) + 1);
        }
        const dangerous =
          /chrome\.(cookies|tabs|webRequest|history|identity|scripting|downloads)/;
        const hasDangerous = [...counts.keys()].some((api) =>
          dangerous.test(api),
        );
        const top = [...counts.entries()]
          .sort((a, b) => b[1] - a[1])
          .slice(0, 8)
          .map(([api, n]) => `${api} (×${n})`);

        labels.push({
          category: 'dynamic_api',
          title: 'Uso de APIs sensibles de Chrome',
          description: `La extensión invocó ${chromeCalls.length} llamada(s) a APIs internas de Chrome desde su service worker.`,
          severity: hasDangerous ? RiskLevel.HIGH : RiskLevel.MEDIUM,
          evidence: top,
        });
      }

      // ── Honeypot Specific Detection ───────────────────────────────────────
      const bankExfiltration = dynamicResult.evidence.networkRequests.filter(
        (r) => {
          const body = r.body?.toLowerCase() ?? '';
          return (
            r.context === 'DOM_FALSIFICATION' &&
            (body.includes('sofia.rozo') ||
              body.includes('5423-8801') ||
              body.includes('tesis2025'))
          );
        },
      );

      if (bankExfiltration.length > 0) {
        labels.push({
          category: 'honeypot_hit',
          title: 'Exfiltración de Datos Financieros',
          description:
            '¡CRÍTICO! La extensión capturó y envió datos del formulario del BancoDemo (correo, cuenta o clave).',
          severity: RiskLevel.CRITICAL,
          evidence: bankExfiltration.map(
            (r) => `Datos enviados a: ${r.url} (Prueba: BancoDemo)`,
          ),
        });
      }

      const sessionTheft = dynamicResult.evidence.networkRequests.filter(
        (r) => r.context === 'STATE_INJECTION' && r.origin === 'extension',
      );
      if (sessionTheft.length > 0) {
        labels.push({
          category: 'session_theft',
          title: 'Robo de Sesión Detectado',
          description:
            'La extensión intentó comunicarse con servidores externos mientras una sesión inyectada (Google/Instagram) estaba activa.',
          severity: RiskLevel.HIGH,
          evidence: sessionTheft
            .slice(0, 5)
            .map((r) => `Actividad sospechosa en: ${r.url}`),
        });
      }
    }

    // Sort by severity
    labels.sort(
      (a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity],
    );

    return labels;
  }

  private calculateOverallRisk(
    staticResult: StaticAnalysisResult,
    dynamicResult: DynamicAnalysisResult | null,
    threatIntelResults: ThreatIntelResult[],
  ): RiskLevel {
    let maxSeverity = 0;

    for (const finding of staticResult.findings) {
      maxSeverity = Math.max(maxSeverity, SEVERITY_ORDER[finding.severity]);
    }

    // Critical domains targeting escalates risk
    const hasRestrictedDomains = staticResult.discoveredDomains.some(
      (d) => d.platformLevel === 3,
    );
    const hasDangerousPatterns = staticResult.findings.some(
      (f) =>
        f.category === FindingCategory.DATA_THEFT ||
        (f.category === FindingCategory.KEYLOGGER &&
          SEVERITY_ORDER[f.severity] > SEVERITY_ORDER[RiskLevel.INFORMATIONAL]),
    );
    if (hasRestrictedDomains && hasDangerousPatterns) {
      maxSeverity = Math.max(maxSeverity, SEVERITY_ORDER[RiskLevel.CRITICAL]);
    }

    // Threat intel escalation
    if (threatIntelResults.some((t) => t.isMalicious)) {
      maxSeverity = Math.max(maxSeverity, SEVERITY_ORDER[RiskLevel.CRITICAL]);
    }

    // Dynamic evidence escalation
    if (dynamicResult) {
      const extRequests = dynamicResult.evidence.networkRequests.filter(
        (r) =>
          (r.origin === 'extension' || r.origin === 'unknown') &&
          r.url.startsWith('http'),
      );
      if (extRequests.length > 10) {
        maxSeverity = Math.max(maxSeverity, SEVERITY_ORDER[RiskLevel.HIGH]);
      }
    }

    // Map back to enum
    if (maxSeverity >= SEVERITY_ORDER[RiskLevel.CRITICAL])
      return RiskLevel.CRITICAL;
    if (maxSeverity >= SEVERITY_ORDER[RiskLevel.HIGH]) return RiskLevel.HIGH;
    if (maxSeverity >= SEVERITY_ORDER[RiskLevel.MEDIUM])
      return RiskLevel.MEDIUM;
    if (maxSeverity >= SEVERITY_ORDER[RiskLevel.LOW]) return RiskLevel.LOW;
    return RiskLevel.NONE;
  }

  private buildUrlReputation(
    contactedUrls: string[],
    threatIntelResults: ThreatIntelResult[],
  ): ContactedUrlReputation[] {
    return contactedUrls.map((url) => {
      let hostname = url;
      try {
        hostname = new URL(url).hostname;
      } catch {
        /* keep raw */
      }

      const matches = threatIntelResults.filter((t) => t.domain === hostname);
      const isMalicious = matches.some((t) => t.isMalicious);
      const score =
        matches.length > 0
          ? matches.reduce((sum, t) => sum + (t.score ?? 0), 0) / matches.length
          : 0;
      const providers = matches
        .filter((t) => t.isMalicious)
        .map((t) => t.provider);
      const categories = [
        ...new Set(matches.flatMap((t) => t.categories ?? [])),
      ];

      return { url, hostname, isMalicious, score, providers, categories };
    });
  }

  private extractContactedUrls(
    dynamicResult: DynamicAnalysisResult | null,
  ): string[] {
    if (!dynamicResult) return [];
    // Include both confirmed extension requests AND unknown-origin HTTP requests.
    // Content scripts run in page context so Playwright can't attribute their
    // fetch() calls to chrome-extension://; those appear as 'unknown'. 'browser'
    // origin (Chrome internals, baseline hosts) is intentionally excluded.
    return [
      ...new Set(
        dynamicResult.evidence.networkRequests
          .filter(
            (r) =>
              (r.origin === 'extension' || r.origin === 'unknown') &&
              r.url.startsWith('http'),
          )
          .map((r) => r.url),
      ),
    ];
  }

  private detectAbusedPermissions(
    staticResult: StaticAnalysisResult,
  ): string[] {
    const abused: string[] = [];

    const permissionToFinding: Record<string, FindingCategory[]> = {
      cookies: [FindingCategory.DATA_THEFT],
      tabs: [FindingCategory.DATA_THEFT],
      webRequest: [FindingCategory.EXFILTRATION],
      // storage/alarms are low-risk background ops — using them normally is not abuse
      '<all_urls>': [FindingCategory.DATA_THEFT, FindingCategory.INJECTION],
    };

    for (const perm of staticResult.manifestPermissions) {
      const relatedCategories = permissionToFinding[perm];
      if (!relatedCategories) continue;

      const hasRelatedFinding = staticResult.findings.some((f) =>
        relatedCategories.includes(f.category),
      );

      if (hasRelatedFinding) {
        abused.push(perm);
      }
    }

    return abused;
  }

  private generateRecommendation(overallRisk: RiskLevel): string {
    switch (overallRisk) {
      case RiskLevel.CRITICAL:
        return 'UNINSTALL_IMMEDIATELY';
      case RiskLevel.HIGH:
        return 'UNINSTALL_RECOMMENDED';
      case RiskLevel.MEDIUM:
        return 'REVIEW_BEFORE_USE';
      case RiskLevel.LOW:
        return 'MONITOR';
      case RiskLevel.INFORMATIONAL:
      case RiskLevel.NONE:
      default:
        return 'NO_SIGNIFICANT_RISKS';
    }
  }

  private calculateConfidence(
    staticResult: StaticAnalysisResult,
    dynamicResult: DynamicAnalysisResult | null,
  ): number {
    let confidence = 0.5; // Base: static-only analysis

    if (dynamicResult && !dynamicResult.timedOut) {
      confidence += 0.3; // Dynamic analysis completed
    } else if (dynamicResult?.timedOut) {
      confidence += 0.1; // Partial dynamic analysis
    }

    if (!staticResult.obfuscationDetected) {
      confidence += 0.1; // Code is readable
    }

    if (staticResult.deobfuscationApplied) {
      confidence += 0.05; // Deobfuscation was successful
    }

    if (staticResult.discoveredDomains.length > 0) {
      confidence += 0.05; // Domain context available
    }

    return Math.min(1.0, confidence);
  }

  private generateTestResults(
    dynamicResult: DynamicAnalysisResult | null,
  ): any[] {
    if (!dynamicResult) return [];

    const testResults: any[] = [];

    // Test: BancoDemo (Honeypot)
    const bankExfiltration = dynamicResult.evidence.networkRequests.filter(
      (r) => {
        const body = r.body?.toLowerCase() ?? '';
        const url = r.url.toLowerCase();
        return (
          r.context === 'DOM_FALSIFICATION' &&
          (body.includes('sofia.rozo') ||
            url.includes('sofia.rozo') ||
            body.includes('5423-8801') ||
            url.includes('5423-8801') ||
            body.includes('tesis2025') ||
            url.includes('tesis2025'))
        );
      },
    );

    testResults.push({
      name: 'Captura de Datos Bancarios (BancoDemo)',
      status: bankExfiltration.length > 0 ? 'FAILED' : 'PASSED',
      description:
        bankExfiltration.length > 0
          ? '¡CRÍTICO! La extensión capturó datos del formulario falso (Saldo, Cuenta, Correo) y los envió a un servidor externo.'
          : 'No se detectó captura de datos financieros simulados.',
      severity:
        bankExfiltration.length > 0 ? RiskLevel.CRITICAL : RiskLevel.LOW,
      findings: bankExfiltration.map((r) => {
        const stolenData: string[] = [];
        const body = r.body?.toLowerCase() ?? '';
        if (body.includes('sofia.rozo'))
          stolenData.push('Correo: sofia.rozo@bancodemo.co');
        if (body.includes('5423-8801'))
          stolenData.push('Cuenta: 5423-8801-XXXX');
        if (body.includes('tesis2025'))
          stolenData.push('Contraseña: tesis2025');

        return `Exfiltrado a: ${r.url} | Datos: ${stolenData.join(', ') || 'Payload cifrado/desconocido'}`;
      }),
    });

    // Test: Session Hijacking (Google/Instagram)
    const sessionHits = dynamicResult.evidence.networkRequests.filter(
      (r) =>
        (r.context === 'STATE_INJECTION' || r.url.includes('instagram.com')) &&
        r.origin === 'extension',
    );
    testResults.push({
      name: 'Intento de Secuestro de Cuentas (Instagram/Google)',
      status: sessionHits.length > 0 ? 'FAILED' : 'PASSED',
      description:
        sessionHits.length > 0
          ? 'La extensión detectó la presencia de sesiones sociales (Instagram/Google) e intentó realizar peticiones no autorizadas en segundo plano hacia estos dominios.'
          : 'No se detectó actividad de interceptación de sesiones sociales.',
      severity:
        sessionHits.length > 5
          ? RiskLevel.CRITICAL
          : sessionHits.length > 0
            ? RiskLevel.HIGH
            : RiskLevel.LOW,
      findings: sessionHits
        .slice(0, 5)
        .map(
          (r) =>
            `Acción detectada: [${r.method}] sobre ${r.url} (Contexto: ${r.context || 'interacción directa'})`,
        ),
    });

    return testResults;
  }

  // ─── Score Calculation Logic (§11 de Tesis) ───────────────────────────────

  /**
   * Score 1: Attack Surface
   * Based only on permissions. Critical=25, High=15, Medium=5, Low=1.
   */
  private calculateScore1(permissions: string[]): number {
    let score = 0;
    for (const p of permissions) {
      const meta = CHROME_PERMISSION_DESCRIPTIONS[p];
      if (!meta) continue;
      switch (meta.risk) {
        case RiskLevel.CRITICAL:
          score += 25;
          break;
        case RiskLevel.HIGH:
          score += 15;
          break;
        case RiskLevel.MEDIUM:
          score += 5;
          break;
        case RiskLevel.LOW:
          score += 1;
          break;
      }
    }
    return Math.min(100, Math.max(0, score));
  }

  /**
   * Score 2: Contextual Risk
   * Score 1 adjusted by Agent 3 verdict.
   */
  private calculateScore2(
    score1: number,
    agentAnalysis?: AgentAnalysisResult,
  ): number {
    if (!agentAnalysis?.agent3) return score1;
    const veredicto = agentAnalysis.agent3.veredicto_preliminar;

    let adjustment = 0;
    switch (veredicto) {
      case 'benigna':
        adjustment = -20;
        break;
      case 'sospechosa':
        adjustment = 5;
        break;
      case 'maliciosa':
        adjustment = 30;
        break;
    }
    return Math.min(100, Math.max(0, score1 + adjustment));
  }

  /**
   * Score 3: Confirmed Risk
   * Score 2 adjusted by Agent 4 verdict when available, falling back to
   * honeypot-based heuristic when Agent 4 did not run.
   */
  private calculateScore3(
    score2: number,
    dynamicResult: DynamicAnalysisResult | null,
    agentAnalysis?: AgentAnalysisResult,
  ): number {
    if (!dynamicResult) return score2;

    // Primary signal: Agent 4 veredicto_dinamico (plan §10)
    const agent4Verdict = agentAnalysis?.agent4?.veredicto_dinamico;
    if (agent4Verdict) {
      let adjustment = 0;
      switch (agent4Verdict) {
        case 'benigna':
          adjustment = -25;
          break;
        case 'sospechosa':
          adjustment = 5;
          break;
        case 'maliciosa':
          adjustment = 40;
          break;
      }
      return Math.min(100, Math.max(0, score2 + adjustment));
    }

    // Fallback: heuristic when Agent 4 did not run
    const honeypotHit = dynamicResult.evidence.networkRequests.some(
      (r) => r.context === 'DOM_FALSIFICATION',
    );
    let adjustment = 0;
    if (honeypotHit) {
      adjustment = 40;
    } else if (dynamicResult.evidence.networkRequests.length > 0) {
      adjustment = 5;
    } else {
      adjustment = -25;
    }
    return Math.min(100, Math.max(0, score2 + adjustment));
  }
}
