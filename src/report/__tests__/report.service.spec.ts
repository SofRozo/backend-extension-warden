import { Test, TestingModule } from '@nestjs/testing';
import { ReportService } from '../report.service.js';
import { StructuredLogger } from '../../common/logger/logger.service.js';
import {
  StaticAnalysisResult,
  DynamicAnalysisResult,
} from '../../common/interfaces/analysis.interfaces.js';
import {
  RiskLevel,
  FindingCategory,
  DetonationStrategy,
  PlatformLevel,
} from '../../common/enums/risk-level.enum.js';

const makeStaticResult = (overrides?: Partial<StaticAnalysisResult>): StaticAnalysisResult => ({
  findings: [],
  discoveredDomains: [],
  domSelectors: [],
  manifestPermissions: [],
  manifestHostPermissions: [],
  crxHash: 'abc123',
  obfuscationDetected: false,
  deobfuscationApplied: false,
  ...overrides,
});

describe('ReportService', () => {
  let service: ReportService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [ReportService, StructuredLogger],
    }).compile();

    service = module.get<ReportService>(ReportService);
  });

  describe('generateReport', () => {
    it('should return INFORMATIONAL risk for clean extension', () => {
      const report = service.generateReport(
        'job-1', 'abcdefghijklmnopqrstuvwxyzabcdef',
        makeStaticResult(), null, [], 5000,
      );
      expect(report.overallRisk).toBe(RiskLevel.INFORMATIONAL);
      expect(report.recommendation).toContain('NO SIGNIFICANT RISKS');
    });

    it('should return CRITICAL risk when critical findings + restricted domains', () => {
      const result = makeStaticResult({
        findings: [{
          category: FindingCategory.DATA_THEFT,
          pattern: 'document.querySelector',
          description: 'Accesses password fields',
          severity: RiskLevel.CRITICAL,
          location: { file: 'inject.js', line: 10, column: 0 },
        }],
        discoveredDomains: [{
          domain: 'bancolombia.com',
          source: 'code',
          context: 'fetch bancolombia',
          platformLevel: PlatformLevel.LEVEL_3_RESTRICTED,
          category: 'banking',
        }],
      });

      const report = service.generateReport('job-2', 'ext123', result, null, [], 5000);
      expect(report.overallRisk).toBe(RiskLevel.CRITICAL);
      expect(report.recommendation).toContain('UNINSTALL IMMEDIATELY');
    });

    it('should return CRITICAL risk when threat intel flags domain', () => {
      const report = service.generateReport(
        'job-3', 'ext456', makeStaticResult(), null,
        [{
          domain: 'phishing-site.com',
          provider: 'virustotal',
          isMalicious: true,
          score: 0.95,
          queriedAt: new Date(),
        }],
        5000,
      );
      expect(report.overallRisk).toBe(RiskLevel.CRITICAL);
    });

    it('should include privacy labels per finding category', () => {
      const result = makeStaticResult({
        findings: [
          {
            category: FindingCategory.KEYLOGGER,
            pattern: 'keyup',
            description: 'Keylogger detected',
            severity: RiskLevel.CRITICAL,
            location: { file: 'bg.js', line: 5, column: 0 },
          },
          {
            category: FindingCategory.EXFILTRATION,
            pattern: 'fetch',
            description: 'Data exfiltration',
            severity: RiskLevel.HIGH,
            location: { file: 'bg.js', line: 10, column: 0 },
          },
        ],
      });

      const report = service.generateReport('job-4', 'ext789', result, null, [], 5000);
      const categories = report.privacyLabels.map(l => l.category);
      expect(categories).toContain(FindingCategory.KEYLOGGER);
      expect(categories).toContain(FindingCategory.EXFILTRATION);
    });

    it('should include restricted domains in privacy labels', () => {
      const result = makeStaticResult({
        discoveredDomains: [{
          domain: 'chase.com',
          source: 'code',
          context: 'https://chase.com/account',
          platformLevel: PlatformLevel.LEVEL_3_RESTRICTED,
          category: 'banking',
        }],
      });

      const report = service.generateReport('job-5', 'ext000', result, null, [], 5000);
      const domainLabel = report.privacyLabels.find(l => l.category === FindingCategory.DOMAIN_TARGETING);
      expect(domainLabel).toBeDefined();
      expect(domainLabel!.severity).toBe(RiskLevel.CRITICAL);
    });

    it('should include dynamic network evidence in labels', () => {
      const dynamicResult: DynamicAnalysisResult = {
        strategy: DetonationStrategy.PASSIVE_TRIGGER,
        evidence: {
          networkRequests: Array.from({ length: 12 }, (_, i) => ({
            url: `https://evil.com/track/${i}`,
            method: 'POST',
            headers: {},
            timestamp: Date.now(),
            origin: 'extension' as const,
          })),
          domMutations: [{ type: 'childList', target: 'DIV', timestamp: Date.now() }],
          keyboardEvents: [],
          apiCalls: [],
        },
        duration: 10000,
        timedOut: false,
      };

      const report = service.generateReport('job-6', 'ext111', makeStaticResult(), dynamicResult, [], 15000);
      const networkLabel = report.privacyLabels.find(l => l.category === 'dynamic_network');
      expect(networkLabel).toBeDefined();
      expect(networkLabel!.severity).toBe(RiskLevel.HIGH);
    });

    it('should calculate lower confidence when obfuscation detected', () => {
      const obfResult = makeStaticResult({ obfuscationDetected: true });
      const cleanResult = makeStaticResult({ obfuscationDetected: false });

      const obfReport = service.generateReport('j1', 'e1', obfResult, null, [], 5000);
      const cleanReport = service.generateReport('j2', 'e2', cleanResult, null, [], 5000);

      expect(cleanReport.confidence).toBeGreaterThan(obfReport.confidence);
    });

    it('should detect abused permissions', () => {
      const result = makeStaticResult({
        manifestPermissions: ['cookies', 'tabs', 'storage'],
        findings: [{
          category: FindingCategory.DATA_THEFT,
          pattern: 'document.cookie',
          description: 'Cookie access',
          severity: RiskLevel.CRITICAL,
          location: { file: 'bg.js', line: 1, column: 0 },
        }],
      });

      const report = service.generateReport('job-7', 'ext222', result, null, [], 5000);
      expect(report.abusedPermissions).toContain('cookies');
    });

    it('should contain all required report fields (RF07)', () => {
      const report = service.generateReport('job-8', 'ext333', makeStaticResult(), null, [], 5000);
      expect(report).toHaveProperty('jobId');
      expect(report).toHaveProperty('overallRisk');
      expect(report).toHaveProperty('privacyLabels');
      expect(report).toHaveProperty('staticFindings');
      expect(report).toHaveProperty('threatIntelResults');
      expect(report).toHaveProperty('contactedUrls');
      expect(report).toHaveProperty('abusedPermissions');
      expect(report).toHaveProperty('recommendation');
      expect(report).toHaveProperty('confidence');
    });
  });
});
