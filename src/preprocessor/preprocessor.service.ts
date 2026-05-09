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
  RemoteCodeViolation,
} from '../common/interfaces/analysis.interfaces.js';

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

    // Classify JS files referenced from the popup HTML that are not declared
    // in the manifest directly (e.g. bundled via <script src="...">) as 'popup'.
    // Also collect external <script src="https://..."> tags as MV3 policy violations.
    const { localScripts, externalScripts } = this.parsePopupScripts(
      extractPath,
      manifest.popupUrl,
    );
    for (const scriptPath of localScripts) {
      if (!roleMap.has(scriptPath)) {
        roleMap.set(scriptPath, 'popup');
      }
    }
    for (const src of externalScripts) {
      remoteCodeViolations.push({
        htmlFile: manifest.popupUrl ?? 'popup.html',
        externalSrc: src,
      });
      if (manifest.manifestVersion === 3) {
        this.logger.logWithJob(
          jobId,
          'warn',
          `MV3 policy violation: external script "${src}" loaded from "${manifest.popupUrl}" — remote code execution is forbidden in Manifest V3`,
          'PreprocessorService',
        );
      }
    }

    const jsFiles = this.findJsFiles(extractPath);

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
      const urls = this.extractUrls(cleanCode);

      files.push({
        path: relativePath,
        role,
        isObfuscated: finalIsObfuscated,
        cleanCode,
        urls,
        domains: this.extractDomains(cleanCode),
        chromeApis: this.extractChromeApis(cleanCode),
        usesFetch: this.usesFetch(cleanCode),
        usesXHR: this.usesXHR(cleanCode),
        usesEval: this.usesEval(cleanCode),
        usesDomManipulation: this.usesDomManipulation(cleanCode),
      });
    }

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

    return {
      manifestVersion: mv === 3 ? 3 : 2,
      name: (raw.name as string) ?? '',
      version: (raw.version as string) ?? '',
      description: raw.description as string | undefined,
      author: raw.author as string | undefined,
      apiPermissions,
      hostPermissions,
      contentScripts,
      backgroundScripts,
      serviceWorker,
      popupUrl: action.default_popup,
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

    return map;
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
   * Reads the popup HTML and returns:
   * - localScripts: relative paths (from extension root) of local <script src="..."> tags,
   *   used to assign the 'popup' role to bundled JS not declared directly in the manifest.
   * - externalScripts: full URLs of external <script src="https://..."> tags.
   *   In MV3, loading remote code from HTML is a policy violation and must be flagged.
   */
  private parsePopupScripts(
    extractPath: string,
    popupUrl: string | undefined,
  ): { localScripts: string[]; externalScripts: string[] } {
    if (!popupUrl) return { localScripts: [], externalScripts: [] };

    const htmlPath = path.join(extractPath, popupUrl);
    let html: string;
    try {
      html = fs.readFileSync(htmlPath, 'utf-8');
    } catch {
      return { localScripts: [], externalScripts: [] };
    }

    const popupDir = path.dirname(popupUrl).replace(/\\/g, '/');
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

  private extractUrls(code: string): string[] {
    const urlRegex =
      /https?:\/\/[a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+(?:\/[^\s'"`,;)\]}>]*)?/g;
    return [...new Set(code.match(urlRegex) ?? [])];
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

  private emptyFile(
    filePath: string,
    role: FileRole,
    isObfuscated: boolean,
  ): ProcessedFile {
    return {
      path: filePath,
      role,
      isObfuscated,
      urls: [],
      domains: [],
      chromeApis: [],
      usesFetch: false,
      usesXHR: false,
      usesEval: false,
      usesDomManipulation: false,
    };
  }
}
