import { Injectable } from '@nestjs/common';
import { AstParserService } from './ast-parser/ast-parser.service.js';
import { DomainClassifierService } from './domain-classifier.service.js';
import { StructuredLogger } from '../common/logger/logger.service.js';
import {
  PreprocessorOutput,
  FileRole,
  PreprocessingFinding,
  StaticDiscoveryType,
  DomainFinding,
} from '../common/interfaces/analysis.interfaces.js';
import { RiskLevel } from '../common/enums/risk-level.enum.js';

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
  async analyze(
    preprocessed: PreprocessorOutput,
    jobId: string,
  ): Promise<void> {
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

    for (const archive of preprocessed.nestedArchives) {
      result1.push(
        this.enrichFinding({
          fileType: 'unknown',
          filePath: archive.path,
          discoveryType: 'archivo_anidado',
          detail: archive.detail,
          line: archive.line,
        }),
      );
    }

    for (const perm of preprocessed.manifest.permissionRisk) {
      if (perm.category === 'low') continue;
      result1.push(
        this.enrichFinding({
          fileType: 'manifest',
          filePath: 'manifest.json',
          discoveryType: 'permiso_chrome_manifest_riesgoso',
          detail: `${perm.permission} (${perm.category}, weight=${perm.weight}, hostSensitive=${perm.hostSensitive}, ${perm.source})`,
          line: this.findManifestLine(
            preprocessed.manifest.rawManifest,
            [perm.source],
            perm.permission,
          ),
        }),
      );
    }

    for (const orphan of preprocessed.dependencyGraph.orphanScripts) {
      result1.push(
        this.enrichFinding({
          fileType: roleByPath.get(orphan) ?? 'unknown',
          filePath: orphan,
          discoveryType: 'archivo_huerfano',
          detail:
            'JavaScript file is not reachable from manifest, HTML, imports, workers, or script injection graph',
          line: 1,
        }),
      );
    }

    for (const unresolved of preprocessed.dependencyGraph.unresolved) {
      result1.push(
        this.enrichFinding({
          fileType: roleByPath.get(unresolved.from) ?? 'unknown',
          filePath: unresolved.from,
          discoveryType: 'dependencia_no_resuelta',
          detail: `${unresolved.type} -> ${unresolved.to}`,
          line: unresolved.line,
        }),
      );
    }

    // ── 1. MV3 remote-script violations → resultado1 ──────────────────────────
    for (const violation of preprocessed.remoteCodeViolations) {
      result1.push(
        this.enrichFinding({
          fileType: 'popup',
          filePath: violation.htmlFile,
          discoveryType: 'script_remoto_mv3',
          detail: violation.externalSrc,
          line: 1,
          codeSnippet: `<script src="${violation.externalSrc}">`,
        }),
      );
    }

    // ── 2. Per-file analysis ──────────────────────────────────────────────────
    for (const file of preprocessed.files) {
      if (file.role === 'library') continue;

      // Obfuscated files: surface the obfuscation as a finding and skip semantic analysis.
      if (file.isObfuscated) {
        result1.push(
          this.enrichFinding({
            fileType: file.role,
            filePath: file.path,
            discoveryType: 'codigo_ofuscado',
            detail: 'archivo ofuscado o agresivamente minificado',
            line: 1,
          }),
        );
        continue;
      }

      if (file.isMinified) {
        result1.push(
          this.enrichFinding({
            fileType: file.role,
            filePath: file.path,
            discoveryType: 'archivo_minificado',
            detail:
              'archivo minificado; line mappings preserved but findings may be dense',
            line: 1,
          }),
        );
      }

      if (!file.cleanCode) continue;

      // 2a. chrome.* API calls — only used internally to detect declared-but-unused
      // permissions. We do NOT emit these as findings: every meaningful extension
      // uses chrome.* APIs and surfacing them is noise. The real signal comes from
      // permission combinations (correlateRisks) and AST patterns (2b/2c).
      for (const api of file.chromeApis) {
        const root = api.api.replace(/^chrome\./, '').split('.')[0];
        if (declaredPermissions.has(root)) {
          usedManifestPermissions.add(root);
        }
      }

      // 2b. AST-driven dangerous JS patterns
      try {
        const { findings } = this.astParser.parseFile(
          file.cleanCode,
          file.path,
        );
        for (const f of findings) {
          result1.push(
            this.enrichFinding({
              fileType: roleByPath.get(f.location.file) ?? file.role,
              filePath: f.location.file,
              discoveryType: this.mapAstDiscoveryType(f.pattern),
              detail: f.pattern,
              line: f.location.line,
              codeSnippet: f.codeSnippet,
              confidence: f.confidence,
              category: f.category,
              severity: this.normalizeSeverity(f.severity),
              why: f.description,
            }),
          );
        }

        // 2c. Taint flow (page-data → network sink) — skip popup
        if (file.role !== 'popup') {
          const flows = this.astParser.detectDataFlow(
            file.cleanCode,
            file.path,
          );
          for (const f of flows) {
            result1.push(
              this.enrichFinding({
                fileType: roleByPath.get(f.location.file) ?? file.role,
                filePath: f.location.file,
                discoveryType: 'flujo_datos_a_red',
                detail: f.description,
                line: f.location.line,
                codeSnippet: f.codeSnippet,
                confidence: f.confidence ?? 0.9,
                category: f.category,
                severity: 'critical',
                why: f.description,
              }),
            );
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

      // 2d. Domain extraction → resultado2. CRITICAL: we use AST to extract
      // ONLY domains that appear as arguments to network sinks (fetch, XHR,
      // WebSocket, sendBeacon, chrome.*sendMessage). URLs in `window.open`,
      // `chrome.tabs.create`, `<a href>`, image/script src, etc. are NOT
      // contacts — they are navigation affordances. We deliberately skip them
      // to avoid flagging "Síguenos en Instagram" buttons as exfiltration.
      try {
        const contacted = this.astParser.extractContactedDomains(
          file.cleanCode,
          file.path,
        );
        file.contactedDomains = contacted;
        for (const d of contacted) {
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
          // 'propio_extension' and 'infraestructura_tecnica' are dropped.
        }
      } catch (err) {
        this.logger.logWithJob(
          jobId,
          'warn',
          `Domain extraction AST error for ${file.path}: ${err instanceof Error ? err.message : String(err)}`,
          'StaticAnalysisService',
        );
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
      result1.push(
        this.enrichFinding({
          fileType: 'manifest',
          filePath: 'manifest.json',
          discoveryType: 'permiso_chrome_manifest_no_usado',
          detail: perm,
          line: this.findManifestLine(
            preprocessed.manifest.rawManifest,
            ['permissions'],
            perm,
          ),
        }),
      );
    }

    // ── 5. Correlate risks (multi-signal patterns) ──────────────────────────
    result1.push(...this.correlateRisks(preprocessed, result1));

    // ── 6. Contextual filter: drop role-incompatible noise ──────────────────
    const filesWithNetworkSink = this.computeFilesWithNetworkSink(
      preprocessed,
      result1,
    );
    const filtered = this.applyContextualFilters(
      result1,
      filesWithNetworkSink,
      roleByPath,
    );

    // ── 7. Recompute confidence per finding with full context ───────────────
    const contextualised = filtered.map((f) =>
      this.recomputeConfidence(
        f,
        roleByPath.get(f.filePath) ?? f.fileType,
        filesWithNetworkSink,
      ),
    );

    // ── 8. Dedupe ───────────────────────────────────────────────────────────
    preprocessed.resultado1 = this.dedupeStaticFindings(contextualised);
    preprocessed.resultado2_priority = this.dedupeDomainFindings(priority);
    preprocessed.resultado2_unknown = this.dedupeDomainFindings(unknown);
    preprocessed.riskScore = this.scoreRisk(
      preprocessed,
      preprocessed.resultado1,
      preprocessed.resultado2_priority,
      preprocessed.resultado2_unknown,
    );

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
      pattern.includes('createElement') ||
      pattern.includes('script.src') ||
      pattern.includes('executeScript')
    ) {
      return 'inyeccion_dom';
    }
    if (
      pattern.includes('fetch') ||
      pattern.includes('sendBeacon') ||
      pattern.includes('WebSocket') ||
      pattern.includes('axios') ||
      pattern.includes('XMLHttpRequest')
    ) {
      return 'funcion_javascript_riesgosa';
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

  private enrichFinding(finding: PreprocessingFinding): PreprocessingFinding {
    const severity = finding.severity ?? this.defaultSeverity(finding);
    return {
      ...finding,
      severity,
      category: finding.category ?? this.defaultCategory(finding),
      why: finding.why ?? this.defaultWhy(finding),
      confidence: finding.confidence ?? this.defaultConfidence(finding),
      scoreImpact:
        finding.scoreImpact ?? this.defaultScoreImpact(finding, severity),
    };
  }

  private defaultSeverity(
    finding: PreprocessingFinding,
  ): 'low' | 'medium' | 'high' | 'critical' {
    if (finding.discoveryType === 'flujo_datos_a_red') return 'critical';
    if (
      finding.discoveryType === 'codigo_ofuscado' ||
      finding.discoveryType === 'script_remoto_mv3'
    )
      return 'high';
    if (finding.discoveryType === 'permiso_chrome_manifest_riesgoso') {
      if (finding.detail.includes('critical')) return 'critical';
      if (finding.detail.includes('high')) return 'high';
      return 'medium';
    }
    if (
      finding.discoveryType === 'archivo_anidado' ||
      finding.discoveryType === 'dependencia_no_resuelta'
    )
      return 'medium';
    if (
      finding.discoveryType === 'archivo_huerfano' ||
      finding.discoveryType === 'archivo_minificado'
    )
      return 'low';
    return 'medium';
  }

  private defaultCategory(finding: PreprocessingFinding): string {
    if (finding.discoveryType.includes('permiso')) return 'manifest';
    if (
      finding.discoveryType.includes('archivo') ||
      finding.discoveryType.includes('dependencia')
    )
      return 'normalization';
    if (finding.discoveryType === 'flujo_datos_a_red') return 'taint';
    if (finding.discoveryType === 'correlacion_riesgo') return 'correlation';
    return 'static';
  }

  private defaultWhy(finding: PreprocessingFinding): string {
    const reasons: Record<StaticDiscoveryType, string> = {
      permiso_chrome_manifest_no_usado:
        'The extension declares a Chrome API permission that static analysis did not observe in reachable code.',
      permiso_chrome_manifest_riesgoso:
        'The manifest declares a permission that grants sensitive browser or host capability.',
      uso_api_chrome: 'The code calls a privileged Chrome extension API.',
      funcion_javascript_riesgosa:
        'The code uses a JavaScript primitive commonly involved in execution, messaging, or exfiltration.',
      flujo_datos_a_red:
        'AST taint analysis found sensitive source data reaching a network or messaging sink.',
      codigo_ofuscado:
        'The code contains obfuscation or aggressive minification signals that reduce auditability.',
      archivo_minificado:
        'The file is minified; line numbers are retained, but dense code can hide behavior.',
      archivo_huerfano:
        'The script exists in the package but is not reachable from the constructed dependency graph.',
      archivo_anidado:
        'Nested archives can hide secondary payloads or delayed unpacking behavior.',
      dependencia_no_resuelta:
        'A referenced local dependency could not be found after path normalization.',
      script_remoto_mv3:
        'Manifest V3 extensions are not allowed to load remotely hosted executable scripts.',
      listener_teclado:
        'Keyboard/input listeners in content contexts can be used for credential capture.',
      inyeccion_dom:
        'DOM or script injection can modify pages, phish users, or execute attacker-controlled code.',
      lectura_cookies: 'Cookie access can expose session identifiers.',
      lectura_storage_navegador:
        'Browser storage often contains auth tokens, preferences, and application state.',
      correlacion_riesgo:
        'Multiple suspicious signals co-occur in a way that materially increases malware likelihood.',
    };
    return reasons[finding.discoveryType];
  }

  private defaultConfidence(finding: PreprocessingFinding): number {
    if (finding.discoveryType === 'flujo_datos_a_red') return 0.9;
    if (finding.discoveryType === 'script_remoto_mv3') return 0.95;
    if (finding.discoveryType === 'correlacion_riesgo') return 0.88;
    return 0.75;
  }

  private defaultScoreImpact(
    finding: PreprocessingFinding,
    severity: string,
  ): number {
    if (finding.discoveryType === 'flujo_datos_a_red') return 10;
    if (finding.detail.includes('<all_urls>')) return 2;
    if (finding.detail.includes('cookies')) return 4;
    if (finding.detail.includes('history')) return 3;
    const weightMatch = finding.detail.match(/weight=(10|5|2|1)/);
    if (weightMatch) return Number(weightMatch[1]);
    if (
      finding.detail.includes('eval') ||
      finding.detail.includes('new Function')
    )
      return 5;
    if (finding.discoveryType === 'codigo_ofuscado') return 4;
    if (finding.detail.toLowerCase().includes('password')) return 8;
    if (finding.discoveryType === 'correlacion_riesgo') return 8;
    return severity === 'critical'
      ? 7
      : severity === 'high'
        ? 5
        : severity === 'medium'
          ? 2
          : 1;
  }

  private normalizeSeverity(
    level: RiskLevel,
  ): 'low' | 'medium' | 'high' | 'critical' {
    if (level === RiskLevel.CRITICAL) return 'critical';
    if (level === RiskLevel.HIGH) return 'high';
    if (level === RiskLevel.MEDIUM) return 'medium';
    return 'low';
  }

  /**
   * Returns the set of file paths that contain a network sink (fetch, sendBeacon,
   * WebSocket, axios, XMLHttpRequest.send). Used to gate role filters: e.g. a
   * keydown listener in a popup is UX noise UNLESS the same file also exfiltrates.
   */
  private computeFilesWithNetworkSink(
    preprocessed: PreprocessorOutput,
    findings: PreprocessingFinding[],
  ): Set<string> {
    const NET_SINK_RE =
      /fetch|sendBeacon|WebSocket|axios|XMLHttpRequest|EventSource/;
    const paths = new Set<string>();
    for (const f of findings) {
      if (NET_SINK_RE.test(f.detail)) paths.add(f.filePath);
      if (f.discoveryType === 'flujo_datos_a_red') paths.add(f.filePath);
    }
    for (const file of preprocessed.files) {
      if (file.usesFetch || file.usesXHR) paths.add(file.path);
    }
    return paths;
  }

  /**
   * Filters out role-context noise that would otherwise dominate the report.
   * Each rule has a clear rationale rooted in extension architecture:
   * - keyboard listeners in popup/options_ui/side_panel without a network sink
   *   are UX (autocomplete, shortcuts). With a sink they stay (potential keylogger
   *   exfiltration).
   * - innerHTML/document.write in popup/options_ui/side_panel without a sink is
   *   UI rendering. Combined with a sink it remains (stored XSS / phishing).
   * - "permiso declarado pero no usado" with severity=low is housekeeping; we
   *   drop it to reduce noise (a manifest declaration alone is rarely meaningful).
   */
  private applyContextualFilters(
    findings: PreprocessingFinding[],
    filesWithSink: Set<string>,
    roleByPath: Map<string, FileRole>,
  ): PreprocessingFinding[] {
    const UI_ROLES: FileRole[] = [
      'popup',
      'options_ui',
      'side_panel',
      'devtools',
    ];
    return findings.filter((f) => {
      const role = roleByPath.get(f.filePath) ?? f.fileType;
      const hasSinkInFile = filesWithSink.has(f.filePath);

      // 1. Key listeners in UI surfaces without a sink: drop (UX normal).
      if (
        f.discoveryType === 'listener_teclado' &&
        UI_ROLES.includes(role) &&
        !hasSinkInFile
      ) {
        return false;
      }
      // 2. DOM injection in UI surfaces without a sink: drop (UI render).
      if (
        f.discoveryType === 'inyeccion_dom' &&
        UI_ROLES.includes(role) &&
        !hasSinkInFile
      ) {
        return false;
      }
      // 3. chrome.storage access in UI surfaces without a sink: drop (legit state).
      if (
        f.discoveryType === 'lectura_storage_navegador' &&
        UI_ROLES.includes(role) &&
        !hasSinkInFile
      ) {
        return false;
      }
      // 4. Low-severity housekeeping that adds no signal:
      if (
        f.discoveryType === 'permiso_chrome_manifest_no_usado' &&
        (f.severity === 'low' || !f.severity)
      ) {
        return false;
      }
      // 5. Minified library files: drop. We already filter `library` role earlier
      // but some minified bundles slip through as `unknown`.
      if (f.discoveryType === 'archivo_minificado' && role === 'unknown') {
        return false;
      }
      return true;
    });
  }

  /**
   * Recomputes the confidence score using file role and surrounding evidence.
   * The previous version returned a flat number per discoveryType; this version
   * tiers it: same finding is highly confident in content_script and weak in popup.
   */
  private recomputeConfidence(
    finding: PreprocessingFinding,
    role: FileRole,
    filesWithSink: Set<string>,
  ): PreprocessingFinding {
    const hasSinkInFile = filesWithSink.has(finding.filePath);
    let confidence = finding.confidence ?? this.defaultConfidence(finding);

    switch (finding.discoveryType) {
      case 'listener_teclado':
        // Content-script keylistener + sink in same file: near-certain keylogger.
        if (role === 'content_script' && hasSinkInFile) confidence = 0.97;
        else if (role === 'content_script') confidence = 0.7;
        else if (role === 'background') confidence = 0.55;
        else confidence = 0.45;
        break;
      case 'inyeccion_dom':
        if (role === 'content_script' && hasSinkInFile) confidence = 0.92;
        else if (role === 'content_script') confidence = 0.7;
        else confidence = 0.55;
        break;
      case 'lectura_cookies':
        // Cookie read in content_script that also exfiltrates is the textbook
        // session-stealer pattern.
        if (role === 'content_script' && hasSinkInFile) confidence = 0.95;
        else if (hasSinkInFile) confidence = 0.85;
        else confidence = 0.6;
        break;
      case 'lectura_storage_navegador':
        if (hasSinkInFile) confidence = 0.8;
        else confidence = 0.45;
        break;
      case 'codigo_ofuscado':
        // Obfuscation in user-side code has no legitimate use case.
        if (role === 'content_script') confidence = 0.97;
        else if (role === 'background') confidence = 0.9;
        else confidence = 0.85;
        break;
      case 'script_remoto_mv3':
        confidence = 0.98;
        break;
      case 'flujo_datos_a_red':
        confidence = 0.92;
        break;
      case 'correlacion_riesgo':
        // Correlation findings already carry their own confidence — leave alone.
        break;
      case 'funcion_javascript_riesgosa':
        if (/eval|new Function/.test(finding.detail)) {
          if (role === 'content_script') confidence = 0.9;
          else confidence = 0.75;
        } else if (hasSinkInFile && role === 'content_script') {
          confidence = 0.8;
        } else {
          confidence = 0.55;
        }
        break;
      case 'permiso_chrome_manifest_riesgoso':
        // A declared permission on its own is rarely a confirmed risk — many
        // legitimate extensions need `scripting`, `tabs`, `webRequest`, etc.
        // We keep these findings around for context (and the agent reads them),
        // but they should NOT surface as "positivo confirmado" by themselves.
        // The correlation rules upstream are what raise confidence when a
        // permission co-occurs with abuse-indicating code patterns.
        if (finding.detail.includes('critical')) confidence = 0.45;
        else if (finding.detail.includes('high')) confidence = 0.3;
        else confidence = 0.15;
        break;
      default:
        // Leave others as-is.
        break;
    }

    return { ...finding, confidence: Math.min(1, Math.max(0, confidence)) };
  }

  /**
   * Multi-signal correlation rules. Each rule combines a manifest fact (permission,
   * host, MV version) with an in-code signal (sink, listener, source) so the
   * finding is grounded in real evidence, not in a single permission existing.
   *
   * Rules are tiered by confidence: 0.95 = near-certain abuse pattern,
   * 0.85 = strong indicator, 0.7 = warrants attention.
   *
   * The `line` field points at the most-supporting in-code finding when
   * available, else falls back to the manifest line.
   */
  private correlateRisks(
    preprocessed: PreprocessorOutput,
    findings: PreprocessingFinding[],
  ): PreprocessingFinding[] {
    const correlated: PreprocessingFinding[] = [];
    const perms = new Set([
      ...preprocessed.manifest.apiPermissions,
      ...preprocessed.manifest.hostPermissions,
      ...preprocessed.manifest.optionalPermissions,
    ]);
    const hostPerms = new Set(preprocessed.manifest.hostPermissions);
    const hasAllUrls =
      hostPerms.has('<all_urls>') ||
      hostPerms.has('*://*/*') ||
      preprocessed.manifest.contentScripts.some((cs) =>
        cs.matches.some((m) => m === '<all_urls>' || m === '*://*/*'),
      );

    const findFinding = (predicate: (f: PreprocessingFinding) => boolean) =>
      findings.find(predicate);
    const findingsMatching = (
      predicate: (f: PreprocessingFinding) => boolean,
    ) => findings.filter(predicate);

    /**
     * Same-file co-occurrence. Returns one of the findings that satisfies
     * predA from a file where ALSO at least one finding satisfies predB.
     * Critical: a cookie read in `bg.js` and a fetch in `popup.js` do NOT
     * imply exfiltration; only same-file co-occurrence does.
     */
    const findFindingWithSamefile = (
      predA: (f: PreprocessingFinding) => boolean,
      predB: (f: PreprocessingFinding) => boolean,
    ): PreprocessingFinding | undefined => {
      const aByPath = new Map<string, PreprocessingFinding>();
      for (const f of findings) if (predA(f)) aByPath.set(f.filePath, f);
      if (aByPath.size === 0) return undefined;
      for (const f of findings)
        if (predB(f) && aByPath.has(f.filePath)) return aByPath.get(f.filePath);
      return undefined;
    };

    const FETCH_RE =
      /fetch|sendBeacon|WebSocket|axios|XMLHttpRequest|EventSource/;
    const EVAL_RE =
      /eval|new Function|setTimeout\(string\)|setInterval\(string\)/;
    const PASSWORD_RE =
      /password|credential selector|credential string|credential template|\.value/;

    const isFetch = (f: PreprocessingFinding) => FETCH_RE.test(f.detail);
    const isEval = (f: PreprocessingFinding) => EVAL_RE.test(f.detail);
    const isPassword = (f: PreprocessingFinding) => PASSWORD_RE.test(f.detail);
    const isCookie = (f: PreprocessingFinding) =>
      f.discoveryType === 'lectura_cookies';
    const isStorage = (f: PreprocessingFinding) =>
      f.discoveryType === 'lectura_storage_navegador';
    const isKeyListener = (f: PreprocessingFinding) =>
      f.discoveryType === 'listener_teclado' &&
      (f.fileType === 'content_script' || f.fileType === 'background');
    const isDomInjection = (f: PreprocessingFinding) =>
      f.discoveryType === 'inyeccion_dom' && f.fileType === 'content_script';

    // Whole-bundle helpers — still used by Tier B rules that combine a manifest
    // permission with ANY presence of a sink (the permission applies globally,
    // so finding a sink anywhere in the extension is enough).
    const fetchFinding = findFinding(isFetch);
    const evalFinding = findFinding(isEval);
    const storageFinding = findFinding(isStorage);
    const domInjectionFinding = findFinding(isDomInjection);
    const dataFlowFinding = findFinding(
      (f) => f.discoveryType === 'flujo_datos_a_red',
    );

    const hasExternalDomain = preprocessed.files.some((f) =>
      (f.extractedUrls ?? []).some((u) =>
        [
          'unknown',
          'suspicious_tld',
          'raw_ip',
          'non_https',
          'dynamic',
        ].includes(u.classification.category),
      ),
    );
    const externalUrlSample = preprocessed.files.flatMap((f) =>
      (f.extractedUrls ?? []).filter((u) =>
        ['suspicious_tld', 'raw_ip', 'non_https', 'dynamic'].includes(
          u.classification.category,
        ),
      ),
    );
    const hasObfuscation = preprocessed.hasObfuscation;

    const isUiOnlySurface =
      !preprocessed.manifest.popupUrl &&
      !preprocessed.manifest.optionsPage &&
      preprocessed.manifest.sandboxPages.length === 0 &&
      Object.keys(preprocessed.manifest.chromeUrlOverrides).length === 0 &&
      preprocessed.manifest.contentScripts.length > 0;

    const add = (params: {
      detail: string;
      filePath?: string;
      line?: number;
      severity?: 'low' | 'medium' | 'high' | 'critical';
      confidence: number;
    }) => {
      correlated.push(
        this.enrichFinding({
          fileType: 'manifest',
          filePath: params.filePath ?? 'manifest.json',
          discoveryType: 'correlacion_riesgo',
          detail: params.detail,
          line: params.line ?? 1,
          severity: params.severity ?? 'critical',
          confidence: params.confidence,
        }),
      );
    };

    // ── Tier A — near-certain abuse patterns (confidence 0.93-0.98) ─────────
    // Tier A REQUIRES same-file co-occurrence: a cookie read in bg.js and a
    // fetch in popup.js are NOT evidence of exfiltration on their own.
    // The deterministic AST taint pass (`flujo_datos_a_red`) is the stronger
    // signal here, but these correlations still help when the taint engine
    // missed a connection.

    // A1: cookie read + network sink in SAME FILE = session exfiltration
    const cookieFetchSameFile = findFindingWithSamefile(isCookie, isFetch);
    if (cookieFetchSameFile) {
      add({
        detail: `cookie access (${cookieFetchSameFile.detail}) co-located with a network sink in the same file — classic session exfiltration pattern`,
        filePath: cookieFetchSameFile.filePath,
        line: cookieFetchSameFile.line,
        confidence: 0.96,
      });
    }

    // A2: keylogger pattern — keylistener + network sink in SAME FILE
    const keyloggerFetchSameFile = findFindingWithSamefile(
      isKeyListener,
      isFetch,
    );
    if (keyloggerFetchSameFile) {
      add({
        detail: `keyboard listener (${keyloggerFetchSameFile.detail}) + network sink in same file — keylogger pattern`,
        filePath: keyloggerFetchSameFile.filePath,
        line: keyloggerFetchSameFile.line,
        confidence: 0.95,
      });
    }

    // A3: password-field selector + network sink in SAME FILE = credential theft
    const passwordFetchSameFile = findFindingWithSamefile(isPassword, isFetch);
    if (passwordFetchSameFile) {
      add({
        detail: `credential field access (${passwordFetchSameFile.detail}) + network sink in same file — credential theft pattern`,
        filePath: passwordFetchSameFile.filePath,
        line: passwordFetchSameFile.line,
        confidence: 0.96,
      });
    }

    // A4: MV3 remote-script violation already gets a dedicated finding;
    // surface a correlation if it co-occurs with credential signals anywhere
    // (remote-script policy violation is itself critical regardless of file).
    const remoteScriptViolations = preprocessed.remoteCodeViolations.length;
    const anyPasswordFinding = findFinding(isPassword);
    const anyCookieFinding = findFinding(isCookie);
    if (
      remoteScriptViolations > 0 &&
      (anyPasswordFinding || anyCookieFinding)
    ) {
      add({
        detail: `MV3 policy violation (remote script) + credential/cookie access in extension`,
        confidence: 0.94,
      });
    }

    // A5: obfuscated content_script + network sink in SAME FILE = stealth exfil
    const obfuscatedSinkSameFile = findFindingWithSamefile(
      (f) =>
        f.discoveryType === 'codigo_ofuscado' &&
        f.fileType === 'content_script',
      isFetch,
    );
    if (obfuscatedSinkSameFile) {
      add({
        detail: `obfuscated content script (${obfuscatedSinkSameFile.filePath}) co-occurring with network sink in same file — stealth exfiltration pattern`,
        filePath: obfuscatedSinkSameFile.filePath,
        line: obfuscatedSinkSameFile.line,
        confidence: 0.93,
      });
    }

    // ── Tier B — strong indicators (confidence 0.82-0.9) ────────────────────

    // B1: <all_urls> + webRequest + fetch = traffic interception capability used
    if (
      hasAllUrls &&
      (perms.has('webRequest') || perms.has('webRequestBlocking')) &&
      fetchFinding
    ) {
      add({
        detail: `<all_urls> + webRequest permission + network sink — traffic interception pipeline`,
        severity: 'critical',
        confidence: 0.88,
      });
    }

    // B2: tabCapture / pageCapture permission + network sink = screen exfiltration
    if (
      (perms.has('tabCapture') ||
        perms.has('pageCapture') ||
        perms.has('desktopCapture')) &&
      fetchFinding
    ) {
      add({
        detail: `screen-capture permission (${[...perms].filter((p) => /Capture$/i.test(p)).join(', ')}) + network sink — screen/page exfiltration risk`,
        confidence: 0.9,
      });
    }

    // B3: nativeMessaging + network sink = bridge to local executable
    if (perms.has('nativeMessaging') && fetchFinding) {
      add({
        detail: `nativeMessaging permission + network sink — extension can bridge browser data to a local executable AND a remote server`,
        confidence: 0.87,
      });
    }

    // B4: proxy / vpnProvider permission = MitM capability flag (any usage)
    if (perms.has('proxy') || perms.has('vpnProvider')) {
      add({
        detail: `proxy/vpnProvider permission present — extension can redirect or inspect all browser traffic`,
        severity: 'high',
        confidence: 0.82,
      });
    }

    // B5: debugger permission + network sink = debugger-API misuse
    if (perms.has('debugger') && fetchFinding) {
      add({
        detail: `debugger permission + network sink — Chrome DevTools Protocol abuse risk`,
        confidence: 0.88,
      });
    }

    // B6: clipboardRead + network sink in SAME FILE
    const clipboardFetchSameFile = findFindingWithSamefile(
      (f) => perms.has('clipboardRead'),
      isFetch,
    );
    if (clipboardFetchSameFile) {
      add({
        detail: `clipboardRead permission + network sink in same file (${clipboardFetchSameFile.filePath}) — clipboard exfiltration risk`,
        confidence: 0.9,
      });
    }

    // B7: history permission + network sink in SAME FILE
    const historyFetchSameFile = findFindingWithSamefile(
      (f) => perms.has('history'),
      isFetch,
    );
    if (historyFetchSameFile) {
      add({
        detail: `history permission + network sink in same file (${historyFetchSameFile.filePath}) — full browsing history exfiltration risk`,
        confidence: 0.87,
      });
    }

    // B8: webRequest/declarativeNetRequest + obfuscation
    if (
      hasObfuscation &&
      (perms.has('webRequest') ||
        perms.has('webRequestBlocking') ||
        perms.has('declarativeNetRequest'))
    ) {
      add({
        detail: `obfuscation + network-rewriting permission — hidden ad/data injection or redirect pattern`,
        confidence: 0.86,
      });
    }

    // B9: chrome.scripting + suspicious external URL
    if (perms.has('scripting') && externalUrlSample.length > 0) {
      const sample = externalUrlSample[0];
      add({
        detail: `chrome.scripting permission + suspicious URL (${sample.url}, ${sample.classification.category})`,
        confidence: 0.84,
      });
    }

    // B10: data_flow finding (taint result) already strong — boost with manifest context
    if (dataFlowFinding && hasAllUrls) {
      add({
        detail: `AST-detected sensitive-data flow + <all_urls> host access — extension can read & exfiltrate from every site`,
        filePath: dataFlowFinding.filePath,
        line: dataFlowFinding.line,
        confidence: 0.92,
      });
    }

    // ── Tier C — patterns warranting attention (confidence 0.7-0.82) ────────

    // C1: history/tabs permission + dynamic code execution
    if ((perms.has('history') || perms.has('tabs')) && evalFinding) {
      add({
        detail: `history/tabs permission + dynamic code execution (${evalFinding.detail}) — browsing data could influence runtime code`,
        severity: 'high',
        filePath: evalFinding.filePath,
        line: evalFinding.line,
        confidence: 0.78,
      });
    }

    // C2: cookie permission alone (no in-code sink yet) = capability flag
    if (perms.has('cookies') && !anyCookieFinding && !fetchFinding) {
      add({
        detail: `cookies permission declared but no cookie read or sink observed — verify whether the permission is actually needed`,
        severity: 'medium',
        confidence: 0.6,
      });
    }

    // C3: ghost extension — content_script on broad matches with zero UI
    if (isUiOnlySurface && hasAllUrls) {
      add({
        detail: `extension declares content_scripts on <all_urls>/*://*/* but has no popup, options, sandbox, or override pages — runs invisibly across all browsing`,
        severity: 'high',
        confidence: 0.83,
      });
    }

    // C4: storage + obfuscation = hidden persistent state
    if (storageFinding && hasObfuscation) {
      add({
        detail: `obfuscated storage access — extension persists state without making the schema auditable`,
        filePath: storageFinding.filePath,
        line: storageFinding.line,
        confidence: 0.78,
      });
    }

    // C5: DOM injection in content_script + external suspicious URL
    if (domInjectionFinding && externalUrlSample.length > 0) {
      const sample = externalUrlSample[0];
      add({
        detail: `DOM injection in content_script + suspicious external URL (${sample.url}) — possible drive-by injection of remote content`,
        filePath: domInjectionFinding.filePath,
        line: domInjectionFinding.line,
        confidence: 0.82,
      });
    }

    // C6: obfuscation + eval (any role) — kept from previous rule set
    if (hasObfuscation && evalFinding) {
      add({
        detail: `obfuscation + runtime code execution (${evalFinding.detail}) — code intentionally hides what it executes`,
        filePath: evalFinding.filePath,
        line: evalFinding.line,
        confidence: 0.85,
      });
    }

    // C7: multiple credential-related findings co-occurring
    const credentialFindings = findingsMatching((f) =>
      /password|credential|wallet|seed|privatekey|metamask|bearer|token/i.test(
        f.detail,
      ),
    );
    if (credentialFindings.length >= 2) {
      add({
        detail: `${credentialFindings.length} credential-related signals in code — extension references sensitive secrets in multiple places`,
        filePath: credentialFindings[0].filePath,
        line: credentialFindings[0].line,
        severity: 'high',
        confidence: 0.8,
      });
    }

    // C8: raw IP host or suspicious TLD in extension code at all
    if (externalUrlSample.length > 0) {
      const ipOrSus = externalUrlSample.find(
        (u) =>
          u.classification.category === 'raw_ip' ||
          u.classification.category === 'suspicious_tld',
      );
      if (ipOrSus) {
        add({
          detail: `extension code references ${ipOrSus.classification.category} URL (${ipOrSus.url}) — bare IPs and uncommon TLDs are infrastructure red flags`,
          severity: 'high',
          confidence: 0.8,
        });
      }
    }

    // Keep the legacy umbrella rule in case some combination escaped the
    // tier-specific rules above.
    if (
      (perms.has('cookies') || hasAllUrls) &&
      hasExternalDomain &&
      fetchFinding &&
      !anyCookieFinding // already covered by A1 if cookieFinding exists
    ) {
      add({
        detail: `cookies/<all_urls> permission + suspicious external domain + network sink — possible exfiltration path even without observed cookie read`,
        confidence: 0.85,
      });
    }

    return correlated;
  }

  private scoreRisk(
    preprocessed: PreprocessorOutput,
    findings: PreprocessingFinding[],
    priority: DomainFinding[],
    unknown: DomainFinding[],
  ): PreprocessorOutput['riskScore'] {
    const reasons: string[] = [];
    let score = 0;
    for (const finding of findings) {
      score += finding.scoreImpact ?? 0;
      if ((finding.scoreImpact ?? 0) >= 5)
        reasons.push(`${finding.discoveryType}: ${finding.detail}`);
    }
    for (const file of preprocessed.files) {
      for (const url of file.extractedUrls ?? []) {
        if (url.classification.category === 'non_https') score += 2;
        if (url.classification.category === 'raw_ip') score += 5;
        if (url.classification.category === 'suspicious_tld') score += 3;
        if (url.classification.category === 'dynamic') score += 2;
      }
    }
    // Cap domain contributions to avoid inflation from many unknown subdomains
    score += Math.min(20, priority.length * 2 + unknown.length);
    const level =
      score >= 45
        ? 'CRITICAL'
        : score >= 25
          ? 'HIGH'
          : score >= 12
            ? 'MEDIUM'
            : 'LOW';
    return { score, level, reasons: [...new Set(reasons)].slice(0, 12) };
  }
}
