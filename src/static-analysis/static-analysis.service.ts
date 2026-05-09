import { Injectable } from '@nestjs/common';
import { AstParserService } from './ast-parser/ast-parser.service.js';
import { DomainClassifierService } from '../agents/agent2/domain-classifier.service.js';
import { StructuredLogger } from '../common/logger/logger.service.js';
import {
  PreprocessorOutput,
  FileRole,
  PreprocessingFinding,
  StaticDiscoveryType,
  DomainFinding,
} from '../common/interfaces/analysis.interfaces.js';

@Injectable()
export class StaticAnalysisService {
  constructor(
    private readonly astParser: AstParserService,
    private readonly domainClassifier: DomainClassifierService,
    private readonly logger: StructuredLogger,
  ) {}

  /**
   * Mutates `preprocessed` to fill resultado1 / resultado2_priority /
   * resultado2_unknown. Each finding carries {fileType, filePath, line,
   * discoveryType, detail}.
   */
  async analyze(preprocessed: PreprocessorOutput, jobId: string): Promise<void> {
    this.logger.logWithJob(
      jobId,
      'info',
      'Starting static analysis',
      'StaticAnalysisService',
    );

    const result1: PreprocessingFinding[] = [];
    const priority: DomainFinding[] = [];
    const unknown: DomainFinding[] = [];

    const roleByPath = new Map<string, FileRole>(
      preprocessed.files.map((f) => [f.path, f.role]),
    );

    // Track which manifest permissions are exercised in code so we can flag the
    // ones that were declared but never called.
    const usedManifestPermissions = new Set<string>();
    const declaredPermissions = new Set(preprocessed.manifest.apiPermissions);

    // ── 1. MV3 remote-script violations → resultado1 ──────────────────────────
    for (const violation of preprocessed.remoteCodeViolations) {
      result1.push({
        fileType: 'popup',
        filePath: violation.htmlFile,
        discoveryType: 'script_remoto_mv3',
        detail: violation.externalSrc,
        line: 1,
        codeSnippet: `<script src="${violation.externalSrc}">`,
      });
    }

    // ── 2. Per-file analysis ──────────────────────────────────────────────────
    for (const file of preprocessed.files) {
      if (file.role === 'library') continue;

      // Obfuscated files: surface the obfuscation as a finding and skip semantic analysis.
      if (file.isObfuscated) {
        result1.push({
          fileType: file.role,
          filePath: file.path,
          discoveryType: 'codigo_ofuscado',
          detail: 'archivo ofuscado o agresivamente minificado',
          line: 1,
        });
        continue;
      }

      if (!file.cleanCode) continue;

      // 2a. chrome.* API calls → uso_api_chrome (mark permission as used)
      for (const api of file.chromeApis) {
        const root = api.api.replace(/^chrome\./, '').split('.')[0];
        if (declaredPermissions.has(root)) {
          usedManifestPermissions.add(root);
        }
        result1.push({
          fileType: file.role,
          filePath: file.path,
          discoveryType: 'uso_api_chrome',
          detail: api.api,
          line: api.line,
        });
      }

      // 2b. AST-driven dangerous JS patterns
      try {
        const { findings } = this.astParser.parseFile(
          file.cleanCode,
          file.path,
        );
        for (const f of findings) {
          result1.push({
            fileType: roleByPath.get(f.location.file) ?? file.role,
            filePath: f.location.file,
            discoveryType: this.mapAstDiscoveryType(f.pattern),
            detail: f.pattern,
            line: f.location.line,
            codeSnippet: f.codeSnippet,
          });
        }

        // 2c. Taint flow (page-data → network sink) — skip popup
        if (file.role !== 'popup') {
          const flows = this.astParser.detectDataFlow(
            file.cleanCode,
            file.path,
          );
          for (const f of flows) {
            result1.push({
              fileType: roleByPath.get(f.location.file) ?? file.role,
              filePath: f.location.file,
              discoveryType: 'flujo_datos_a_red',
              detail: f.description,
              line: f.location.line,
            });
          }
        }
      } catch (err) {
        this.logger.logWithJob(
          jobId,
          'warn',
          `AST error for ${file.path}: ${err instanceof Error ? err.message : String(err)}`,
          'StaticAnalysisService',
        );
      }

      // 2d. Domain extraction → resultado2
      for (const d of file.domains) {
        const det = this.domainClassifier.classify(
          d.domain,
          preprocessed.manifest.name,
          preprocessed.manifest.author,
        );
        const category = det.category ?? 'desconocido';
        const finding: DomainFinding = {
          fileType: file.role,
          filePath: file.path,
          discoveryType: 'url_en_codigo',
          domain: d.domain,
          category,
          priority: this.domainClassifier.playwrightPriority(category),
          line: d.line,
        };
        if (this.domainClassifier.isPriority(category)) {
          priority.push(finding);
        } else if (category === 'desconocido') {
          unknown.push(finding);
        }
        // 'propio_extension' and 'infraestructura_tecnica' are dropped — they
        // are not interesting to surface to the user.
      }
    }

    // ── 3. Manifest host_permissions → resultado2 ─────────────────────────────
    for (const hp of preprocessed.manifest.hostPermissions) {
      const hostname = this.extractHostFromPattern(hp);
      if (!hostname) continue;
      const det = this.domainClassifier.classify(
        hostname,
        preprocessed.manifest.name,
        preprocessed.manifest.author,
      );
      const category = det.category ?? 'desconocido';
      const finding: DomainFinding = {
        fileType: 'manifest',
        filePath: 'manifest.json',
        discoveryType: 'host_permission_manifest',
        domain: hostname,
        category,
        priority: this.domainClassifier.playwrightPriority(category),
        line: this.findManifestLine(
          preprocessed.manifest.rawManifest,
          ['host_permissions', 'permissions'],
          hp,
        ),
      };
      if (this.domainClassifier.isPriority(category)) {
        priority.push(finding);
      } else if (category === 'desconocido') {
        unknown.push(finding);
      }
    }

    // ── 4. Manifest permissions declared but never used → resultado1 ──────────
    for (const perm of declaredPermissions) {
      if (usedManifestPermissions.has(perm)) continue;
      result1.push({
        fileType: 'manifest',
        filePath: 'manifest.json',
        discoveryType: 'permiso_chrome_manifest_no_usado',
        detail: perm,
        line: this.findManifestLine(
          preprocessed.manifest.rawManifest,
          ['permissions'],
          perm,
        ),
      });
    }

    // ── 5. Dedupe ─────────────────────────────────────────────────────────────
    preprocessed.resultado1 = this.dedupeStaticFindings(result1);
    preprocessed.resultado2_priority = this.dedupeDomainFindings(priority);
    preprocessed.resultado2_unknown = this.dedupeDomainFindings(unknown);

    this.logger.logWithJob(
      jobId,
      'info',
      `Static analysis complete: ${preprocessed.resultado1.length} resultado1, ` +
        `${preprocessed.resultado2_priority.length} priority domains, ` +
        `${preprocessed.resultado2_unknown.length} unknown domains`,
      'StaticAnalysisService',
    );
  }

  // ─── Helpers ───────────────────────────────────────────────────────────────

  /**
   * Maps the legacy AST pattern name onto the new StaticDiscoveryType taxonomy.
   * Multiple legacy patterns collapse to fewer human-readable categories.
   */
  private mapAstDiscoveryType(pattern: string): StaticDiscoveryType {
    if (
      pattern.includes('cookie') ||
      pattern === 'document.cookie' ||
      pattern.startsWith('chrome.cookies')
    ) {
      return 'lectura_cookies';
    }
    if (
      pattern === 'localStorage' ||
      pattern === 'sessionStorage' ||
      pattern.includes('Storage')
    ) {
      return 'lectura_storage_navegador';
    }
    if (
      pattern === 'keydown' ||
      pattern === 'keyup' ||
      pattern === 'keypress' ||
      pattern === 'submit' ||
      pattern === 'input' ||
      pattern === 'change'
    ) {
      return 'listener_teclado';
    }
    if (
      pattern === 'innerHTML' ||
      pattern === 'outerHTML' ||
      pattern.includes('document.write') ||
      pattern.includes('createElement')
    ) {
      return 'inyeccion_dom';
    }
    if (pattern === 'data_flow') return 'flujo_datos_a_red';
    return 'funcion_javascript_riesgosa';
  }

  /**
   * Extracts the hostname from a manifest match pattern such as
   * "https://*.example.com/*" → "example.com".
   */
  private extractHostFromPattern(pattern: string): string | null {
    try {
      const cleaned = pattern.replace(/^\*:\/\//, 'https://');
      const url = new URL(
        cleaned.includes('://') ? cleaned : `https://${cleaned}`,
      );
      const host = url.hostname.replace(/^\*\./, '').replace(/^\*$/, '');
      return host && !host.includes('*') ? host.toLowerCase() : null;
    } catch {
      return null;
    }
  }

  /**
   * Best-effort line number lookup for a manifest entry. Re-serialises the
   * raw manifest with indent=2 and returns the first line that contains the
   * needle within any of the given top-level keys' regions.
   */
  private findManifestLine(
    raw: Record<string, unknown>,
    keys: string[],
    needle: string,
  ): number {
    try {
      const serialised = JSON.stringify(raw, null, 2);
      const lines = serialised.split('\n');
      for (let i = 0; i < lines.length; i++) {
        if (lines[i].includes(needle)) return i + 1;
      }
      void keys;
    } catch {
      /* ignore */
    }
    return 1;
  }

  private dedupeStaticFindings(
    list: PreprocessingFinding[],
  ): PreprocessingFinding[] {
    const seen = new Set<string>();
    return list.filter((f) => {
      const key = `${f.filePath}:${f.line}:${f.discoveryType}:${f.detail}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }

  private dedupeDomainFindings(list: DomainFinding[]): DomainFinding[] {
    const seen = new Set<string>();
    return list.filter((f) => {
      const key = `${f.filePath}:${f.line}:${f.domain}:${f.discoveryType}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }
}
