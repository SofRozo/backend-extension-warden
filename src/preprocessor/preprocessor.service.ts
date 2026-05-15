import { Injectable } from '@nestjs/common';
import * as fs from 'fs';
import * as path from 'path';
import { DeobfuscatorService } from '../static-analysis/deobfuscator/deobfuscator.service.js';
import { StructuredLogger } from '../common/logger/logger.service.js';
import type {
  PreprocessorOutput,
  ManifestInfo,
  ProcessedFile,
  FileRole,
  ExtractedChromeApi,
  ExtractedDomain,
  ExtractedUrl,
  RemoteCodeViolation,
  ResourceInventoryEntry,
  ResourceType,
  DependencyGraph,
  DependencyEdge,
  NestedArchiveFinding,
} from '../common/interfaces/analysis.interfaces.js';

const PERMISSION_RISK_WEIGHTS: Record<
  string,
  {
    category: 'low' | 'medium' | 'high' | 'critical';
    weight: 1 | 2 | 5 | 10;
    hostSensitive: boolean;
  }
> = {
  tabCapture: { category: 'critical', weight: 10, hostSensitive: true },
  pageCapture: { category: 'critical', weight: 10, hostSensitive: true },
  debugger: { category: 'critical', weight: 10, hostSensitive: false },
  nativeMessaging: { category: 'critical', weight: 10, hostSensitive: false },
  proxy: { category: 'critical', weight: 10, hostSensitive: false },
  vpnProvider: { category: 'critical', weight: 10, hostSensitive: false },
  cookies: { category: 'high', weight: 5, hostSensitive: true },
  scripting: { category: 'high', weight: 5, hostSensitive: true },
  declarativeNetRequest: { category: 'high', weight: 5, hostSensitive: true },
  webRequest: { category: 'high', weight: 5, hostSensitive: true },
  webRequestBlocking: { category: 'high', weight: 5, hostSensitive: true },
  userScripts: { category: 'high', weight: 5, hostSensitive: true },
  declarativeNetRequestWithHostAccess: {
    category: 'high',
    weight: 5,
    hostSensitive: true,
  },
  desktopCapture: { category: 'high', weight: 5, hostSensitive: true },
  history: { category: 'high', weight: 5, hostSensitive: false },
  downloads: { category: 'high', weight: 5, hostSensitive: false },
  'downloads.open': { category: 'high', weight: 5, hostSensitive: false },
  privacy: { category: 'high', weight: 5, hostSensitive: false },
  browsingData: { category: 'high', weight: 5, hostSensitive: false },
  contentSettings: { category: 'high', weight: 5, hostSensitive: false },
  webNavigation: { category: 'high', weight: 5, hostSensitive: false },
  webAuthenticationProxy: { category: 'high', weight: 5, hostSensitive: false },
  certificateProvider: { category: 'high', weight: 5, hostSensitive: false },
  platformKeys: { category: 'high', weight: 5, hostSensitive: false },
  activeTab: { category: 'medium', weight: 2, hostSensitive: false },
  alarms: { category: 'medium', weight: 2, hostSensitive: false },
  bookmarks: { category: 'medium', weight: 2, hostSensitive: false },
  clipboardRead: { category: 'medium', weight: 2, hostSensitive: false },
  clipboardWrite: { category: 'medium', weight: 2, hostSensitive: false },
  geolocation: { category: 'medium', weight: 2, hostSensitive: false },
  identity: { category: 'medium', weight: 2, hostSensitive: false },
  'identity.email': { category: 'medium', weight: 2, hostSensitive: false },
  management: { category: 'medium', weight: 2, hostSensitive: false },
  sessions: { category: 'medium', weight: 2, hostSensitive: false },
  topSites: { category: 'medium', weight: 2, hostSensitive: false },
  contextMenus: { category: 'medium', weight: 2, hostSensitive: false },
  tabGroups: { category: 'medium', weight: 2, hostSensitive: false },
  dns: { category: 'medium', weight: 2, hostSensitive: false },
  tabs: { category: 'medium', weight: 2, hostSensitive: false },
  offscreen: { category: 'medium', weight: 2, hostSensitive: false },
  processes: { category: 'medium', weight: 2, hostSensitive: false },
  storage: { category: 'low', weight: 1, hostSensitive: false },
  unlimitedStorage: { category: 'low', weight: 1, hostSensitive: false },
  notifications: { category: 'low', weight: 1, hostSensitive: false },
  idle: { category: 'low', weight: 1, hostSensitive: false },
  power: { category: 'low', weight: 1, hostSensitive: false },
  tts: { category: 'low', weight: 1, hostSensitive: false },
  ttsEngine: { category: 'low', weight: 1, hostSensitive: false },
  fontSettings: { category: 'low', weight: 1, hostSensitive: false },
  declarativeContent: { category: 'low', weight: 1, hostSensitive: false },
  gcm: { category: 'low', weight: 1, hostSensitive: false },
  sidePanel: { category: 'low', weight: 1, hostSensitive: false },
  search: { category: 'low', weight: 1, hostSensitive: false },
  favicon: { category: 'low', weight: 1, hostSensitive: false },
  readingList: { category: 'low', weight: 1, hostSensitive: false },
  printing: { category: 'low', weight: 1, hostSensitive: false },
  printingMetrics: { category: 'low', weight: 1, hostSensitive: false },
  documentScan: { category: 'low', weight: 1, hostSensitive: false },
  loginState: { category: 'low', weight: 1, hostSensitive: false },
  'accessibilityFeatures.modify': {
    category: 'low',
    weight: 1,
    hostSensitive: false,
  },
  'accessibilityFeatures.read': {
    category: 'low',
    weight: 1,
    hostSensitive: false,
  },
  background: { category: 'low', weight: 1, hostSensitive: false },
  declarativeNetRequestFeedback: {
    category: 'low',
    weight: 1,
    hostSensitive: false,
  },
  'downloads.ui': { category: 'low', weight: 1, hostSensitive: false },
  'system.cpu': { category: 'low', weight: 1, hostSensitive: false },
  'system.display': { category: 'low', weight: 1, hostSensitive: false },
  'system.memory': { category: 'low', weight: 1, hostSensitive: false },
  'system.storage': { category: 'low', weight: 1, hostSensitive: false },
  printerProvider: { category: 'low', weight: 1, hostSensitive: false },
};

@Injectable()
export class PreprocessorService {
  constructor(
    private readonly deobfuscator: DeobfuscatorService,
    private readonly logger: StructuredLogger,
  ) {}

  /**
   * Entry point. Validates the extension, classifies every JS file by role,
   * strips comments, detects obfuscation, and extracts structured data.
   * Throws if manifest.json is missing — callers must treat this as a hard failure.
   */
  async preprocess(
    extractPath: string,
    crxHash: string,
    jobId: string,
  ): Promise<PreprocessorOutput> {
    const manifestPath = path.join(extractPath, 'manifest.json');
    if (!fs.existsSync(manifestPath)) {
      throw new Error(
        'Invalid extension: manifest.json not found at extension root',
      );
    }

    let rawManifest: Record<string, unknown>;
    try {
      rawManifest = JSON.parse(fs.readFileSync(manifestPath, 'utf-8'));
    } catch (err) {
      throw new Error(
        `Invalid extension: manifest.json could not be parsed — ${err instanceof Error ? err.message : String(err)}`,
      );
    }

    const manifest = this.parseManifest(rawManifest);
    const roleMap = this.buildRoleMap(manifest);
    const remoteCodeViolations: RemoteCodeViolation[] = [];
    const resources = this.inventoryResources(extractPath);
    const nestedArchives = resources
      .filter((r) => r.type === 'archive')
      .map<NestedArchiveFinding>((r) => ({
        path: r.path,
        line: 1,
        detail: `Nested archive resource detected (${r.sizeBytes} bytes)`,
      }));

    // Classify JS files referenced from HTML pages that are not declared
    // in the manifest directly (e.g. bundled via <script src="...">).
    // Also collect external <script src="https://..."> tags as MV3 policy violations.
    const htmlPages: Array<{ url: string | undefined; role: FileRole }> = [
      { url: manifest.popupUrl, role: 'popup' },
      { url: manifest.optionsPage, role: 'options_ui' },
      { url: manifest.devtoolsPage, role: 'devtools' },
      { url: manifest.sidePanelPath, role: 'side_panel' },
      ...manifest.sandboxPages.map<{ url: string; role: FileRole }>((url) => ({
        url,
        role: 'sandbox',
      })),
      ...Object.values(manifest.chromeUrlOverrides)
        .filter((url): url is string => typeof url === 'string')
        .map<{ url: string; role: FileRole }>((url) => ({
          url,
          role: 'override_page',
        })),
    ];

    for (const { url, role } of htmlPages) {
      const { localScripts, externalScripts } = this.parseHtmlScripts(
        extractPath,
        url,
      );
      for (const scriptPath of localScripts) {
        if (!roleMap.has(scriptPath)) {
          roleMap.set(scriptPath, role);
        }
      }
      for (const src of externalScripts) {
        remoteCodeViolations.push({
          htmlFile: url ?? 'unknown.html',
          externalSrc: src,
        });
        if (manifest.manifestVersion === 3 && role !== 'sandbox') {
          this.logger.logWithJob(
            jobId,
            'warn',
            `MV3 policy violation: external script "${src}" loaded from "${url}" — remote code execution is forbidden in Manifest V3`,
            'PreprocessorService',
          );
        }
      }
    }

    const jsFiles = resources
      .filter((r) => r.type === 'javascript')
      .map((r) => path.join(extractPath, r.path));

    this.logger.logWithJob(
      jobId,
      'info',
      `Preprocessing ${jsFiles.length} JS files (manifest v${manifest.manifestVersion})`,
      'PreprocessorService',
    );

    const files: ProcessedFile[] = [];

    for (const filePath of jsFiles) {
      const relativePath = path
        .relative(extractPath, filePath)
        .replace(/\\/g, '/');
      const role = this.inferRole(relativePath, roleMap);

      if (role === 'library') {
        files.push(this.emptyFile(relativePath, 'library', false));
        continue;
      }

      let rawCode: string;
      try {
        rawCode = fs.readFileSync(filePath, 'utf-8');
      } catch {
        continue;
      }

      // Safety limit: skip extremely large files to prevent worker OOM
      if (rawCode.length > 2 * 1024 * 1024) {
        this.logger.logWithJob(
          jobId,
          'warn',
          `Skipping ${relativePath}: file too large (${(rawCode.length / 1024 / 1024).toFixed(2)} MB)`,
          'PreprocessorService',
        );
        files.push(this.emptyFile(relativePath, role, false));
        continue;
      }

      const isObfuscatedInit =
        this.deobfuscator.isObfuscated(rawCode) ||
        this.isAggressivelyMinified(rawCode);

      let processedCode = rawCode;
      let finalIsObfuscated = isObfuscatedInit;

      if (isObfuscatedInit) {
        const deobResult = this.deobfuscator.deobfuscate(rawCode, relativePath);
        processedCode = deobResult.code;
        finalIsObfuscated = deobResult.wasObfuscated;
      }

      const cleanCode = this.stripComments(processedCode);
      const extractedUrls = this.extractUrls(cleanCode);
      const resourceMeta = resources.find((r) => r.path === relativePath);

      files.push({
        path: relativePath,
        role,
        isObfuscated: finalIsObfuscated,
        isMinified:
          resourceMeta?.isMinified ?? this.isAggressivelyMinified(rawCode),
        originalLineCount: rawCode.split('\n').length,
        cleanCode,
        urls: extractedUrls.map((u) => u.url),
        extractedUrls,
        domains: this.extractDomains(cleanCode),
        chromeApis: this.extractChromeApis(cleanCode),
        usesFetch: this.usesFetch(cleanCode),
        usesXHR: this.usesXHR(cleanCode),
        usesEval: this.usesEval(cleanCode),
        usesDomManipulation: this.usesDomManipulation(cleanCode),
      });
    }

    const dependencyGraph = this.buildDependencyGraph(
      extractPath,
      manifest,
      files,
      resources,
      remoteCodeViolations,
    );

    // Reclassify files referenced by chrome.scripting.executeScript / tabs.executeScript
    // as content_script. These files are injected into web pages at runtime,
    // so their *effective* role IS content_script even though the manifest
    // doesn't declare them as such. Without this, they stay as `unknown` and
    // their AST findings get filtered out aggressively (lectura_teclado,
    // inyeccion_dom, etc. in `unknown` files lose confidence).
    this.reclassifyInjectedScripts(files, dependencyGraph);

    const obfuscatedFileCount = files.filter((f) => f.isObfuscated).length;

    this.logger.logWithJob(
      jobId,
      'info',
      `Preprocessing complete: ${files.length} files processed, ${obfuscatedFileCount} obfuscated`,
      'PreprocessorService',
    );

    return {
      crxHash,
      extractPath,
      manifest,
      files,
      resources,
      nestedArchives,
      dependencyGraph,
      obfuscatedFileCount,
      hasObfuscation: obfuscatedFileCount > 0,
      remoteCodeViolations,
      // Filled by StaticAnalysisService.analyze()
      resultado1: [],
      resultado2_priority: [],
      resultado2_unknown: [],
    };
  }

  // ─── Manifest parsing ────────────────────────────────────────────────────────

  private parseManifest(raw: Record<string, unknown>): ManifestInfo {
    const mv = (raw.manifest_version as number) ?? 2;

    const allPerms = (raw.permissions as string[]) ?? [];
    const optionalPermissions = (raw.optional_permissions as string[]) ?? [];
    const isHostPerm = (p: string) => /^https?:\/\/|\*:\/\/|<all_urls>/.test(p);

    let apiPermissions: string[];
    let hostPermissions: string[];

    if (mv === 3) {
      apiPermissions = allPerms.filter((p) => !isHostPerm(p));
      hostPermissions = [
        ...((raw.host_permissions as string[]) ?? []),
        ...allPerms.filter(isHostPerm),
      ];
    } else {
      // V2: host patterns mixed inside the permissions array
      apiPermissions = allPerms.filter((p) => !isHostPerm(p));
      hostPermissions = allPerms.filter(isHostPerm);
    }

    const rawCs =
      (raw.content_scripts as Array<{
        matches?: string[];
        js?: string[];
        css?: string[];
      }>) ?? [];
    const contentScripts = rawCs.map((cs) => ({
      matches: cs.matches ?? [],
      js: cs.js ?? [],
      css: cs.css,
    }));

    const bg =
      (raw.background as {
        service_worker?: string;
        scripts?: string[];
        js?: string[];
      }) ?? {};
    const backgroundScripts = bg.scripts ?? bg.js ?? [];
    const serviceWorker = bg.service_worker;

    const action =
      ((raw.action ?? raw.browser_action ?? raw.page_action) as {
        default_popup?: string;
      }) ?? {};

    const optionsUi = (raw.options_ui as { page?: string }) ?? {};
    const optionsPage =
      optionsUi.page ?? (raw.options_page as string | undefined);

    const devtoolsPage = raw.devtools_page as string | undefined;

    const sidePanel = (raw.side_panel as { default_path?: string }) ?? {};
    const sidePanelPath = sidePanel.default_path;

    const sandbox = (raw.sandbox as { pages?: string[] }) ?? {};
    const sandboxPages = sandbox.pages ?? [];

    const chromeUrlOverrides =
      (raw.chrome_url_overrides as Record<string, string>) ?? {};

    const webAccessibleResources = Array.isArray(raw.web_accessible_resources)
      ? raw.web_accessible_resources
      : [];
    const externallyConnectable = raw.externally_connectable as
      | Record<string, unknown>
      | undefined;
    const dnr = raw.declarative_net_request as
      | { rule_resources?: Array<{ path?: string }> }
      | undefined;
    const declarativeNetRequestRules =
      dnr?.rule_resources?.map((r) => r.path).filter((p): p is string => !!p) ??
      [];
    const oauth2 = raw.oauth2 as Record<string, unknown> | undefined;

    return {
      manifestVersion: mv === 3 ? 3 : 2,
      name: (raw.name as string) ?? '',
      version: (raw.version as string) ?? '',
      description: raw.description as string | undefined,
      author: raw.author as string | undefined,
      apiPermissions,
      hostPermissions,
      optionalPermissions,
      contentScripts,
      backgroundScripts,
      serviceWorker,
      popupUrl: action.default_popup,
      optionsPage,
      devtoolsPage,
      sidePanelPath,
      sandboxPages,
      chromeUrlOverrides,
      webAccessibleResources,
      externallyConnectable,
      declarativeNetRequestRules,
      oauth2,
      permissionRisk: this.classifyPermissionRisk(
        apiPermissions,
        optionalPermissions,
        hostPermissions,
      ),
      rawManifest: raw,
    };
  }

  // ─── Role classification ──────────────────────────────────────────────────────

  private buildRoleMap(manifest: ManifestInfo): Map<string, FileRole> {
    const map = new Map<string, FileRole>();

    for (const cs of manifest.contentScripts) {
      for (const f of cs.js) {
        map.set(f.replace(/\\/g, '/'), 'content_script');
      }
    }
    for (const f of manifest.backgroundScripts) {
      map.set(f.replace(/\\/g, '/'), 'background');
    }
    if (manifest.serviceWorker) {
      map.set(manifest.serviceWorker.replace(/\\/g, '/'), 'background');
    }
    if (manifest.popupUrl) {
      map.set(manifest.popupUrl.replace(/\\/g, '/'), 'popup');
    }
    if (manifest.optionsPage) {
      map.set(manifest.optionsPage.replace(/\\/g, '/'), 'options_ui');
    }
    if (manifest.devtoolsPage) {
      map.set(manifest.devtoolsPage.replace(/\\/g, '/'), 'devtools');
    }
    if (manifest.sidePanelPath) {
      map.set(manifest.sidePanelPath.replace(/\\/g, '/'), 'side_panel');
    }
    for (const page of manifest.sandboxPages) {
      map.set(page.replace(/\\/g, '/'), 'sandbox');
    }
    for (const page of Object.values(manifest.chromeUrlOverrides)) {
      if (typeof page === 'string') {
        map.set(page.replace(/\\/g, '/'), 'override_page');
      }
    }

    return map;
  }

  /**
   * After the dependency graph is built, promote files referenced by
   * `chrome.scripting.executeScript({ files: [...] })`, `chrome.tabs.executeScript`,
   * or dynamic script injection to `content_script` role.
   *
   * These files literally run inside web pages, but the manifest only declares
   * them indirectly (the API call decides which pages they touch at runtime).
   * Without this promotion they keep their default `unknown` role, which causes:
   *   - confidence downgrade in StaticAnalysisService.recomputeConfidence
   *   - aggressive filtering in StaticAnalysisService.applyContextualFilters
   *   - the user never sees their findings.
   *
   * Library files (jquery.min, lodash, etc.) are left alone — they're still
   * libraries even if injected, and the lib classifier already detected them.
   */
  private reclassifyInjectedScripts(
    files: ProcessedFile[],
    dependencyGraph: DependencyGraph,
  ): void {
    const injectedPaths = new Set<string>();
    for (const edge of dependencyGraph.edges) {
      if (
        edge.type === 'scripting_executeScript' ||
        edge.type === 'script_injection'
      ) {
        injectedPaths.add(edge.to.replace(/\\/g, '/'));
      }
    }
    if (injectedPaths.size === 0) return;

    for (const file of files) {
      if (file.role === 'library') continue;
      // Only promote `unknown` files; don't clobber explicit roles such as
      // `popup`, `options_ui`, `background` etc. that the manifest already
      // declared (an injected popup.js is rare but possible — leave it).
      if (file.role !== 'unknown') continue;
      const normalised = file.path.replace(/\\/g, '/');
      const isInjected =
        injectedPaths.has(normalised) ||
        [...injectedPaths].some(
          (p) => normalised === p || normalised.endsWith('/' + p),
        );
      if (isInjected) {
        file.role = 'content_script';
      }
    }
  }

  private inferRole(
    relativePath: string,
    roleMap: Map<string, FileRole>,
  ): FileRole {
    const norm = relativePath.replace(/\\/g, '/');

    for (const [key, role] of roleMap) {
      if (norm === key || norm.endsWith('/' + key)) return role;
    }

    const basename = norm.split('/').pop()?.toLowerCase() ?? '';
    const KNOWN_LIBS = [
      'jquery',
      'lodash',
      'underscore',
      'html2canvas',
      'react.min',
      'vue.min',
      'angular.min',
      'bootstrap.min',
    ];
    if (KNOWN_LIBS.some((lib) => basename.startsWith(lib))) return 'library';

    const lower = norm.toLowerCase();
    if (
      lower.includes('/popup/') ||
      lower.startsWith('popup/') ||
      lower === 'popup.js'
    )
      return 'popup';
    if (lower.includes('options') || lower.includes('settings'))
      return 'options_ui';
    if (lower.includes('devtools') || lower.includes('panel'))
      return 'devtools';
    if (lower.includes('sandbox')) return 'sandbox';
    if (lower.includes('sidepanel') || lower.includes('side_panel'))
      return 'side_panel';
    if (
      lower.includes('background') ||
      lower.includes('service-worker') ||
      lower.includes('serviceworker')
    )
      return 'background';
    if (
      lower.includes('/content') ||
      lower.includes('content-script') ||
      lower.includes('contentscript')
    )
      return 'content_script';

    return 'unknown';
  }

  // ─── Popup HTML parsing ───────────────────────────────────────────────────────

  /**
   * Reads an HTML file and returns:
   * - localScripts: relative paths (from extension root) of local <script src="..."> tags,
   *   used to assign roles to bundled JS not declared directly in the manifest.
   * - externalScripts: full URLs of external <script src="https://..."> tags.
   *   In MV3, loading remote code from HTML is a policy violation and must be flagged.
   */
  private parseHtmlScripts(
    extractPath: string,
    htmlUrl: string | undefined,
  ): { localScripts: string[]; externalScripts: string[] } {
    if (!htmlUrl) return { localScripts: [], externalScripts: [] };

    const htmlPath = path.join(extractPath, htmlUrl);
    let html: string;
    try {
      html = fs.readFileSync(htmlPath, 'utf-8');
    } catch {
      return { localScripts: [], externalScripts: [] };
    }

    const popupDir = path.dirname(htmlUrl).replace(/\\/g, '/');
    const localScripts: string[] = [];
    const externalScripts: string[] = [];
    const scriptSrcRegex =
      /<script[^>]+src=['"]([^'"]+\.(?:js|mjs))(?:\?[^'"]*)?['"]/gi;
    let m: RegExpExecArray | null;

    while ((m = scriptSrcRegex.exec(html)) !== null) {
      const srcRaw = m[1];
      if (/^https?:\/\//.test(srcRaw)) {
        externalScripts.push(srcRaw); // MV3 policy violation — remote code
        continue;
      }

      let scriptPath: string;
      if (srcRaw.startsWith('/')) {
        scriptPath = srcRaw.slice(1);
      } else {
        scriptPath = popupDir === '.' ? srcRaw : `${popupDir}/${srcRaw}`;
      }
      localScripts.push(scriptPath.replace(/\\/g, '/'));
    }

    return { localScripts, externalScripts };
  }

  // ─── Obfuscation / minification detection ────────────────────────────────────

  private computeShannonEntropy(text: string): number {
    const freq = new Map<string, number>();
    for (const ch of text) {
      freq.set(ch, (freq.get(ch) ?? 0) + 1);
    }
    const len = text.length;
    let entropy = 0;
    for (const count of freq.values()) {
      const p = count / len;
      entropy -= p * Math.log2(p);
    }
    return entropy;
  }

  private isAggressivelyMinified(code: string): boolean {
    const lines = code.split('\n');

    // Any line longer than 5 000 chars is a minification signal
    if (lines.some((l) => l.length > 5000)) return true;

    // Dense hex escape sequences
    const hexEscapes = (code.match(/\\x[0-9a-fA-F]{2}/g) ?? []).length;
    if (hexEscapes > 100) return true;

    // High Shannon entropy on a representative sample — characteristic of encrypted
    // or base64-packed strings.  Readable JS sits at ~4–5 bits/char; base64 ~6;
    // encrypted/random content reaches >7.  Threshold 6.5 catches the latter two.
    const sample = code.slice(0, 4000);
    if (sample.length > 500 && this.computeShannonEntropy(sample) > 6.5)
      return true;

    // Ratio of short identifiers to readable words
    const shortVars = (code.match(/\b[a-z_][a-z_]?\s*=/g) ?? []).length;
    const longWords = (code.match(/\b\w{4,}\b/g) ?? []).length;
    if (longWords > 0 && shortVars / longWords > 0.8) return true;

    return false;
  }

  // ─── Code cleaning ────────────────────────────────────────────────────────────

  private stripComments(code: string): string {
    /**
     * RF02: Strip comments while preserving strings, regexes and newlines.
     * Regex logic:
     * 1. Match string literals (double, single, template) OR regex literals and capture them in group 1.
     * 2. Match block comments and capture them in group 2.
     * 3. Match line comments and capture them in group 3.
     *
     * In the replacer, if group 1 matched, return it as-is.
     * If a block comment matched, return newlines to preserve line numbers.
     * If a line comment matched, return empty string.
     */
    const regex =
      /((?:"(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*'|`(?:[^`\\]|\\.)*`|\/(?![*\/])(?:[^\/\n\\\\]|\\.)+\/[gimyus]*))|(\/\*[\s\S]*?\*\/)|(\/\/[^\n]*)/gs;

    return code.replace(
      regex,
      (_match, literal, blockComment, _lineComment) => {
        if (literal) return literal;
        if (blockComment) {
          return '\n'.repeat((blockComment.match(/\n/g) ?? []).length);
        }
        return '';
      },
    );
  }

  // ─── Structured data extraction ───────────────────────────────────────────────

  private extractUrls(code: string): ExtractedUrl[] {
    const urls: ExtractedUrl[] = [];
    const seen = new Set<string>();
    const lines = code.split('\n');
    const urlRegex =
      /https?:\/\/[a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+(?:\/[^\s'"`,;)\]}>]*)?/g;
    const dynamicUrlRegex =
      /\b(?:fetch|axios(?:\.\w+)?|XMLHttpRequest|WebSocket|EventSource|sendBeacon)\s*\([^)\n]*(?:\+|`|\$\{)/;
    for (let i = 0; i < lines.length; i++) {
      urlRegex.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = urlRegex.exec(lines[i])) !== null) {
        const key = `${m[0]}:${i + 1}`;
        if (seen.has(key)) continue;
        seen.add(key);
        urls.push({
          url: m[0],
          line: i + 1,
          context: lines[i].trim().slice(0, 240),
          classification: this.classifyUrl(m[0]),
        });
      }
      if (dynamicUrlRegex.test(lines[i])) {
        const key = `dynamic:${i + 1}`;
        if (!seen.has(key)) {
          seen.add(key);
          urls.push({
            url: '<dynamic>',
            line: i + 1,
            context: lines[i].trim().slice(0, 240),
            classification: {
              category: 'dynamic',
              reasons: ['URL appears dynamically constructed'],
            },
          });
        }
      }
    }
    return urls;
  }

  private extractDomains(code: string): ExtractedDomain[] {
    const domains: ExtractedDomain[] = [];
    const seen = new Set<string>();
    const lines = code.split('\n');

    // Pattern 1: domains inside URLs (http://example.com/...)
    const urlRegex =
      /https?:\/\/([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)/gi;

    // Pattern 2: bare domain strings ('example.com')
    const bareRegex =
      /['"`]([a-zA-Z0-9][-a-zA-Z0-9]*\.(?:com|org|net|edu|gov|io|co|me|info|biz)(?:\.[a-z]{2,3})?)['"`]/gi;

    for (let i = 0; i < lines.length; i++) {
      const lineText = lines[i];
      const lineNum = i + 1;

      // Reset regex state for each line
      urlRegex.lastIndex = 0;
      bareRegex.lastIndex = 0;

      let m: RegExpExecArray | null;

      // Extract from URLs
      while ((m = urlRegex.exec(lineText)) !== null) {
        const domain = m[1].toLowerCase();
        const key = `${domain}:${lineNum}`;
        if (!seen.has(key)) {
          seen.add(key);
          domains.push({ domain, line: lineNum });
        }
      }

      // Extract bare domains
      while ((m = bareRegex.exec(lineText)) !== null) {
        const domain = m[1].toLowerCase();
        const key = `${domain}:${lineNum}`;
        if (!seen.has(key)) {
          seen.add(key);
          domains.push({ domain, line: lineNum });
        }
      }
    }

    return domains;
  }

  private extractChromeApis(code: string): ExtractedChromeApi[] {
    const apis: ExtractedChromeApi[] = [];
    const seen = new Set<string>();
    const lines = code.split('\n');
    const re = /\bchrome\.([a-zA-Z]+(?:\.[a-zA-Z]+)*)\s*(?:\(|\.)/g;

    for (let i = 0; i < lines.length; i++) {
      re.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = re.exec(lines[i])) !== null) {
        const api = `chrome.${m[1]}`;
        const key = `${api}:${i + 1}`;
        if (!seen.has(key)) {
          seen.add(key);
          apis.push({ api, line: i + 1 });
        }
      }
    }

    return apis;
  }

  private usesFetch(code: string): boolean {
    return /\bfetch\s*\(/.test(code);
  }

  private usesXHR(code: string): boolean {
    return /\bnew\s+XMLHttpRequest\b/.test(code);
  }

  private usesEval(code: string): boolean {
    return /\beval\s*\(/.test(code);
  }

  private usesDomManipulation(code: string): boolean {
    return /\.(innerHTML|outerHTML|innerText|textContent)\s*=/.test(code);
  }

  // ─── Filesystem helpers ───────────────────────────────────────────────────────

  private findJsFiles(dir: string): string[] {
    const files: string[] = [];
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return files;
    }

    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (entry.name === 'node_modules' || entry.name === '_metadata')
          continue;
        files.push(...this.findJsFiles(fullPath));
      } else if (/\.(js|mjs|cjs|jsx)$/i.test(entry.name)) {
        files.push(fullPath);
      }
    }

    return files;
  }

  private inventoryResources(root: string): ResourceInventoryEntry[] {
    const resources: ResourceInventoryEntry[] = [];
    const visit = (dir: string) => {
      let entries: fs.Dirent[];
      try {
        entries = fs.readdirSync(dir, { withFileTypes: true });
      } catch {
        return;
      }
      for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);
        if (entry.isDirectory()) {
          if (entry.name === 'node_modules' || entry.name === '_metadata')
            continue;
          visit(fullPath);
          continue;
        }
        const relative = path.relative(root, fullPath).replace(/\\/g, '/');
        const type = this.resourceType(entry.name);
        let sizeBytes = 0;
        let text = '';
        try {
          const stat = fs.statSync(fullPath);
          sizeBytes = stat.size;
          if (
            ['javascript', 'html', 'json', 'css'].includes(type) &&
            stat.size <= 2 * 1024 * 1024
          ) {
            text = fs.readFileSync(fullPath, 'utf-8');
          }
        } catch {
          /* ignore unreadable resources */
        }
        resources.push({
          path: relative,
          type,
          sizeBytes,
          isMinified:
            (type === 'javascript' || type === 'css') &&
            text.length > 0 &&
            this.isAggressivelyMinified(text),
          lineCount: text ? text.split('\n').length : 0,
        });
      }
    };
    visit(root);
    return resources;
  }

  private resourceType(name: string): ResourceType {
    if (/\.(js|mjs|cjs|jsx)$/i.test(name)) return 'javascript';
    if (/\.html?$/i.test(name)) return 'html';
    if (/\.json$/i.test(name)) return 'json';
    if (/\.css$/i.test(name)) return 'css';
    if (/\.(zip|crx|xpi|7z|rar|tar|gz)$/i.test(name)) return 'archive';
    return 'other';
  }

  private buildDependencyGraph(
    extractPath: string,
    manifest: ManifestInfo,
    files: ProcessedFile[],
    resources: ResourceInventoryEntry[],
    remoteCodeViolations: RemoteCodeViolation[],
  ): DependencyGraph {
    const resourceSet = new Set(resources.map((r) => r.path));
    const jsSet = new Set(files.map((f) => f.path));
    const entries = new Set<string>();
    const edges: DependencyEdge[] = [];
    const unresolved: DependencyEdge[] = [];

    const addManifestEntry = (to: string | undefined) => {
      const normalized = this.normalizeRelativePath(to);
      if (!normalized) return;
      entries.add(normalized);
      edges.push({
        from: 'manifest.json',
        to: normalized,
        type: 'manifest',
        line: 1,
      });
    };

    for (const cs of manifest.contentScripts) {
      for (const js of cs.js) addManifestEntry(js);
      for (const css of cs.css ?? []) addManifestEntry(css);
    }
    for (const bg of manifest.backgroundScripts) addManifestEntry(bg);
    addManifestEntry(manifest.serviceWorker);
    addManifestEntry(manifest.popupUrl);
    addManifestEntry(manifest.optionsPage);
    addManifestEntry(manifest.devtoolsPage);
    addManifestEntry(manifest.sidePanelPath);
    for (const page of manifest.sandboxPages) addManifestEntry(page);
    for (const page of Object.values(manifest.chromeUrlOverrides))
      addManifestEntry(page);
    for (const rulePath of manifest.declarativeNetRequestRules)
      addManifestEntry(rulePath);

    for (const r of resources.filter((x) => x.type === 'html')) {
      for (const edge of this.htmlDependencyEdges(extractPath, r.path)) {
        edges.push(edge);
        if (edge.to.startsWith('http')) continue;
        if (!resourceSet.has(edge.to)) unresolved.push(edge);
      }
    }

    for (const file of files) {
      if (!file.cleanCode) continue;
      for (const edge of this.jsDependencyEdges(file)) {
        edges.push(edge);
        if (!resourceSet.has(edge.to)) unresolved.push(edge);
      }
    }

    const adjacency = new Map<string, DependencyEdge[]>();
    for (const edge of edges) {
      const list = adjacency.get(edge.from) ?? [];
      list.push(edge);
      adjacency.set(edge.from, list);
    }

    const reachable = new Set<string>();
    const queue = [...entries];
    while (queue.length > 0) {
      const current = queue.shift()!;
      if (reachable.has(current)) continue;
      reachable.add(current);
      for (const edge of adjacency.get(current) ?? []) {
        if (!edge.to.startsWith('http') && resourceSet.has(edge.to))
          queue.push(edge.to);
      }
      if (/\.(html?)$/i.test(current)) {
        for (const edge of adjacency.get(current) ?? []) queue.push(edge.to);
      }
    }

    for (const v of remoteCodeViolations) {
      edges.push({
        from: v.htmlFile,
        to: v.externalSrc,
        type: 'html_script',
        line: 1,
      });
    }

    return {
      entries: [...entries],
      edges,
      reachable: [...reachable].filter(
        (p) => resourceSet.has(p) || jsSet.has(p),
      ),
      orphanScripts: [...jsSet].filter((p) => !reachable.has(p)),
      unresolved,
    };
  }

  private htmlDependencyEdges(
    extractPath: string,
    htmlPath: string,
  ): DependencyEdge[] {
    const fullPath = path.join(extractPath, htmlPath);
    let html = '';
    try {
      html = fs.readFileSync(fullPath, 'utf-8');
    } catch {
      return [];
    }
    const dir = path.dirname(htmlPath).replace(/\\/g, '/');
    const edges: DependencyEdge[] = [];
    const scriptRe = /<script[^>]+src=['"]([^'"]+)['"]/gi;
    let m: RegExpExecArray | null;
    while ((m = scriptRe.exec(html)) !== null) {
      const before = html.slice(0, m.index);
      const line = before.split('\n').length;
      const to = /^https?:\/\//i.test(m[1])
        ? m[1]
        : this.resolveRelative(dir, m[1].replace(/\?.*$/, ''));
      edges.push({ from: htmlPath, to, type: 'html_script', line });
    }
    return edges;
  }

  private jsDependencyEdges(file: ProcessedFile): DependencyEdge[] {
    const code = file.cleanCode ?? '';
    const lines = code.split('\n');
    const edges: DependencyEdge[] = [];
    const dir = path.dirname(file.path).replace(/\\/g, '/');

    // ── Single-target patterns (line-by-line) ──
    const patterns: Array<{ re: RegExp; type: DependencyEdge['type'] }> = [
      {
        re: /\bimport\s+(?:[^'"]+\s+from\s+)?['"]([^'"]+)['"]/g,
        type: 'static_import',
      },
      { re: /\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)/g, type: 'dynamic_import' },
      { re: /\brequire\s*\(\s*['"]([^'"]+)['"]\s*\)/g, type: 'require' },
      { re: /\bnew\s+Worker\s*\(\s*['"]([^'"]+)['"]\s*\)/g, type: 'worker' },
      {
        re: /\.src\s*=\s*['"]([^'"]+\.js[^'"]*)['"]/g,
        type: 'script_injection',
      },
    ];
    for (let i = 0; i < lines.length; i++) {
      for (const pattern of patterns) {
        pattern.re.lastIndex = 0;
        let m: RegExpExecArray | null;
        while ((m = pattern.re.exec(lines[i])) !== null) {
          if (!this.isLocalDependency(m[1])) continue;
          edges.push({
            from: file.path,
            to: this.resolveRelative(dir, m[1].replace(/\?.*$/, '')),
            type: pattern.type,
            line: i + 1,
          });
        }
      }
    }

    // ── Multi-target pattern: chrome.scripting.executeScript({ files: [...] }) ──
    // The `files` array can contain MANY scripts and span multiple lines:
    //   files: ["a.js", "b.js"]                         ← multi-file inline
    //   files: [\n  "a.js",\n  "b.js"\n]                ← multiline
    // The previous regex required a single quoted string immediately followed
    // by `]`, so it produced ZERO matches for any real-world case (every MV3
    // extension that injects helpers + main script). We now grab the whole
    // array body and extract every quoted string inside.
    const filesArrayRe = /\bfiles\s*:\s*\[([\s\S]*?)\]/g;
    let fm: RegExpExecArray | null;
    while ((fm = filesArrayRe.exec(code)) !== null) {
      const arrayContent = fm[1];
      const line = code.slice(0, fm.index).split('\n').length;
      const stringRe = /['"]([^'"]+)['"]/g;
      let sm: RegExpExecArray | null;
      while ((sm = stringRe.exec(arrayContent)) !== null) {
        if (!this.isLocalDependency(sm[1])) continue;
        edges.push({
          from: file.path,
          to: this.resolveRelative(dir, sm[1].replace(/\?.*$/, '')),
          type: 'scripting_executeScript',
          line,
        });
      }
    }

    return edges;
  }

  private isLocalDependency(specifier: string): boolean {
    return (
      specifier.startsWith('.') ||
      specifier.startsWith('/') ||
      /\.(js|mjs|cjs|jsx|html?|css|json)$/i.test(specifier)
    );
  }

  private resolveRelative(fromDir: string, specifier: string): string {
    const raw = specifier.startsWith('/')
      ? specifier.slice(1)
      : path.posix.normalize(
          path.posix.join(fromDir === '.' ? '' : fromDir, specifier),
        );
    return raw.replace(/^\.\//, '').replace(/\\/g, '/');
  }

  private normalizeRelativePath(value: string | undefined): string | null {
    if (!value || /^https?:\/\//i.test(value)) return null;
    return value.replace(/^\//, '').replace(/\\/g, '/');
  }

  private classifyPermissionRisk(
    apiPermissions: string[],
    optionalPermissions: string[],
    hostPermissions: string[],
  ): ManifestInfo['permissionRisk'] {
    const classify = (
      permission: string,
    ): {
      category: 'low' | 'medium' | 'high' | 'critical';
      weight: 1 | 2 | 5 | 10;
      hostSensitive: boolean;
    } => {
      if (permission === '<all_urls>' || permission === '*://*/*') {
        return { category: 'critical', weight: 10, hostSensitive: true };
      }
      if (/^https?:\/\/|\*:\/\//.test(permission)) {
        return { category: 'medium', weight: 2, hostSensitive: true };
      }
      return (
        PERMISSION_RISK_WEIGHTS[permission] ?? {
          category: 'medium',
          weight: 2,
          hostSensitive: false,
        }
      );
    };
    return [
      ...apiPermissions.map((permission) => ({
        permission,
        ...classify(permission),
        source: 'permissions' as const,
      })),
      ...optionalPermissions.map((permission) => ({
        permission,
        ...classify(permission),
        source: 'optional_permissions' as const,
      })),
      ...hostPermissions.map((permission) => ({
        permission,
        ...classify(permission),
        source: 'host_permissions' as const,
      })),
    ];
  }

  private classifyUrl(url: string): ExtractedUrl['classification'] {
    try {
      const parsed = new URL(url);
      const domain = parsed.hostname.toLowerCase();
      const reasons: string[] = [];
      const namespaceDomains = [
        'www.w3.org',
        'w3.org',
        'xml.org',
        'schemas.xmlsoap.org',
      ];
      if (namespaceDomains.includes(domain)) {
        return {
          protocol: parsed.protocol,
          domain,
          category: 'trusted',
          reasons: ['XML/SVG namespace, not a network endpoint'],
        };
      }
      const trusted = [
        'googleapis.com',
        'gstatic.com',
        'mozilla.org',
        'microsoft.com',
      ];
      const analytics = [
        'google-analytics.com',
        'googletagmanager.com',
        'segment.io',
        'mixpanel.com',
        'sentry.io',
      ];
      const suspiciousTlds = [
        'zip',
        'mov',
        'top',
        'xyz',
        'click',
        'cam',
        'icu',
        'cyou',
      ];
      const isIp = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(domain);
      const isLocal =
        domain === 'localhost' ||
        domain === '127.0.0.1' ||
        domain.endsWith('.local');
      const tld = domain.split('.').pop() ?? '';
      if (parsed.protocol !== 'https:') reasons.push('non-HTTPS protocol');
      if (isIp) reasons.push('raw IP address');
      if (isLocal) reasons.push('localhost/private development endpoint');
      if (suspiciousTlds.includes(tld)) reasons.push(`suspicious TLD .${tld}`);
      if (trusted.some((d) => domain === d || domain.endsWith(`.${d}`))) {
        return {
          protocol: parsed.protocol,
          domain,
          category: 'trusted',
          reasons,
        };
      }
      if (analytics.some((d) => domain === d || domain.endsWith(`.${d}`))) {
        return {
          protocol: parsed.protocol,
          domain,
          category: 'analytics',
          reasons,
        };
      }
      if (isIp)
        return {
          protocol: parsed.protocol,
          domain,
          category: 'raw_ip',
          reasons,
        };
      if (isLocal)
        return {
          protocol: parsed.protocol,
          domain,
          category: 'localhost',
          reasons,
        };
      if (parsed.protocol !== 'https:')
        return {
          protocol: parsed.protocol,
          domain,
          category: 'non_https',
          reasons,
        };
      if (suspiciousTlds.includes(tld))
        return {
          protocol: parsed.protocol,
          domain,
          category: 'suspicious_tld',
          reasons,
        };
      return {
        protocol: parsed.protocol,
        domain,
        category: 'unknown',
        reasons,
      };
    } catch {
      return {
        category: 'dynamic',
        reasons: ['URL could not be statically parsed'],
      };
    }
  }

  private emptyFile(
    filePath: string,
    role: FileRole,
    isObfuscated: boolean,
  ): ProcessedFile {
    return {
      path: filePath,
      role,
      isObfuscated,
      isMinified: false,
      originalLineCount: 0,
      urls: [],
      extractedUrls: [],
      domains: [],
      chromeApis: [],
      usesFetch: false,
      usesXHR: false,
      usesEval: false,
      usesDomManipulation: false,
    };
  }
}
