import { Injectable } from '@nestjs/common';
import { AstParserService } from './ast-parser/ast-parser.service.js';
import { DomainDiscoveryService } from './domain-discovery/domain-discovery.service.js';
import { StructuredLogger } from '../common/logger/logger.service.js';
import {
  StaticAnalysisResult,
  StaticFinding,
  DiscoveredDomain,
  DomSelector,
  PreprocessorOutput,
  FileRole,
} from '../common/interfaces/analysis.interfaces.js';
import { FindingCategory, RiskLevel } from '../common/enums/risk-level.enum.js';

@Injectable()
export class StaticAnalysisService {
  constructor(
    private readonly astParser: AstParserService,
    private readonly domainDiscovery: DomainDiscoveryService,
    private readonly logger: StructuredLogger,
  ) {}

  async analyze(
    preprocessed: PreprocessorOutput,
    jobId: string,
  ): Promise<StaticAnalysisResult> {
    this.logger.logWithJob(jobId, 'info', 'Starting static analysis', 'StaticAnalysisService');

    const allFindings: StaticFinding[] = [];
    const allDomains: DiscoveredDomain[] = [];
    const allSelectors: DomSelector[] = [];

    // Manifest domains (secondary source — code takes priority)
    allDomains.push(
      ...this.domainDiscovery.extractDomainsFromManifest(preprocessed.manifest.rawManifest),
    );

    // Role lookup for findings calibration
    const roleByPath = new Map<string, FileRole>(
      preprocessed.files.map((f) => [f.path, f.role]),
    );

    // Obfuscated files: presence alone is a finding; skip semantic analysis per spec
    for (const file of preprocessed.files.filter((f) => f.isObfuscated)) {
      allFindings.push({
        category: FindingCategory.DATA_THEFT,
        pattern: 'obfuscated_code',
        description: `File '${file.path}' contains obfuscated or aggressively minified code that conceals its behavior`,
        severity:
          file.role === 'content_script' || file.role === 'unknown'
            ? RiskLevel.HIGH
            : RiskLevel.MEDIUM,
        location: { file: file.path, line: 1, column: 0 },
      });
    }

    const analysisFiles = preprocessed.files.filter(
      (f) => !f.isObfuscated && f.role !== 'library' && f.cleanCode,
    );

    this.logger.logWithJob(
      jobId,
      'info',
      `Analyzing ${analysisFiles.length} files (${preprocessed.obfuscatedFileCount} obfuscated, skipped)`,
      'StaticAnalysisService',
    );

    for (const file of analysisFiles) {
      try {
        const { findings, selectors } = this.astParser.parseFile(
          file.cleanCode!,
          file.path,
        );
        allFindings.push(...findings);
        allSelectors.push(...selectors);

        // Skip taint analysis for popup — it only touches its own isolated DOM
        if (file.role !== 'popup') {
          allFindings.push(
            ...this.astParser.detectDataFlow(file.cleanCode!, file.path),
          );
        }

        allDomains.push(
          ...this.domainDiscovery.extractDomainsFromCode(file.cleanCode!, file.path),
        );
      } catch (err) {
        this.logger.logWithJob(
          jobId,
          'warn',
          `Error analyzing ${file.path}: ${err instanceof Error ? err.message : String(err)}`,
          'StaticAnalysisService',
        );
      }
    }

    const uniqueFindings = this.adjustFindingsByRole(
      this.deduplicateFindings(allFindings),
      roleByPath,
    );
    const uniqueDomains = this.deduplicateDomains(allDomains);

    this.logger.logWithJob(
      jobId,
      'info',
      `Static analysis complete: ${uniqueFindings.length} findings, ${uniqueDomains.length} domains`,
      'StaticAnalysisService',
    );

    return {
      findings: uniqueFindings,
      discoveredDomains: uniqueDomains,
      domSelectors: allSelectors,
      manifestPermissions: preprocessed.manifest.apiPermissions,
      manifestHostPermissions: preprocessed.manifest.hostPermissions,
      crxHash: preprocessed.crxHash,
      obfuscationDetected: preprocessed.hasObfuscation,
      deobfuscationApplied: false,
    };
  }



  private adjustFindingsByRole(
    findings: StaticFinding[],
    roleByPath: Map<string, FileRole>,
  ): StaticFinding[] {
    return findings
      .filter((f) => (roleByPath.get(f.location.file) ?? 'unknown') !== 'library')
      .map((f) =>
        this.applyRoleSeverity(f, roleByPath.get(f.location.file) ?? 'unknown'),
      );
  }

  private applyRoleSeverity(
    finding: StaticFinding,
    role: string,
  ): StaticFinding {
    // 0 = content_script / unknown (highest risk), 1 = background, 2 = popup
    const idx = role === 'popup' ? 2 : role === 'background' ? 1 : 0;


    switch (finding.category) {
      case FindingCategory.KEYLOGGER: {
        const isFormEvent = ['submit', 'input', 'change'].includes(finding.pattern);
        const t: [RiskLevel, RiskLevel, RiskLevel] = isFormEvent
          ? [RiskLevel.MEDIUM, RiskLevel.LOW, RiskLevel.INFORMATIONAL]
          : [RiskLevel.HIGH, RiskLevel.LOW, RiskLevel.INFORMATIONAL];
        return { ...finding, severity: t[idx] };
      }
      case FindingCategory.DATA_THEFT: {
        if (idx === 0) return finding;
        const isSensitive =
          finding.pattern.includes('cookie') || finding.description.includes('password');
        const t: [RiskLevel, RiskLevel, RiskLevel] = isSensitive
          ? [finding.severity, RiskLevel.HIGH, RiskLevel.MEDIUM]
          : [finding.severity, RiskLevel.LOW, RiskLevel.INFORMATIONAL];
        return { ...finding, severity: t[idx] };
      }
      case FindingCategory.INJECTION: {
        if (idx === 0) return finding;
        const t: [RiskLevel, RiskLevel, RiskLevel] = [
          finding.severity, RiskLevel.MEDIUM, RiskLevel.INFORMATIONAL,
        ];
        return { ...finding, severity: t[idx] };
      }
      case FindingCategory.EXFILTRATION: {
        if (idx === 0) return finding;
        const isSendBeacon = finding.pattern.includes('sendBeacon');
        const t: [RiskLevel, RiskLevel, RiskLevel] = isSendBeacon
          ? [finding.severity, RiskLevel.CRITICAL, RiskLevel.HIGH]
          : [finding.severity, RiskLevel.MEDIUM, RiskLevel.LOW];
        return { ...finding, severity: t[idx] };
      }
      default:
        return finding;
    }
  }

  private deduplicateFindings(findings: StaticFinding[]): StaticFinding[] {
    const seen = new Set<string>();
    return findings.filter((f) => {
      const key = `${f.category}:${f.pattern}:${f.location.file}:${f.location.line}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }

  private deduplicateDomains(domains: DiscoveredDomain[]): DiscoveredDomain[] {
    const seen = new Set<string>();
    return domains.filter((d) => {
      if (seen.has(d.domain)) return false;
      seen.add(d.domain);
      return true;
    });
  }
}
