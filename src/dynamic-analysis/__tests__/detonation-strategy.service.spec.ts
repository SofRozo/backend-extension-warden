import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import {
  DetonationStrategyService,
  DetonationPlan,
} from '../detonation-strategies/detonation-strategy.service.js';
import { StructuredLogger } from '../../common/logger/logger.service.js';
import { EncryptionService } from '../../common/crypto/encryption.service.js';
import {
  StaticAnalysisResult,
  DiscoveredDomain,
  DomSelector,
} from '../../common/interfaces/analysis.interfaces.js';
import {
  DetonationStrategy,
  PlatformLevel,
  FindingCategory,
  RiskLevel,
} from '../../common/enums/risk-level.enum.js';

const makeStaticResult = (
  overrides?: Partial<StaticAnalysisResult>,
): StaticAnalysisResult => ({
  findings: [],
  discoveredDomains: [],
  domSelectors: [],
  manifestPermissions: [],
  manifestHostPermissions: [],
  crxHash: 'hash123',
  obfuscationDetected: false,
  deobfuscationApplied: false,
  ...overrides,
});

describe('DetonationStrategyService', () => {
  let service: DetonationStrategyService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        DetonationStrategyService,
        StructuredLogger,
        {
          provide: ConfigService,
          useValue: {
            get: jest.fn(() => undefined),
          },
        },
      ],
    }).compile();

    service = module.get<DetonationStrategyService>(DetonationStrategyService);
  });

  describe('selectStrategy', () => {
    it('should return PASSIVE_TRIGGER for generic sites when no domains found', () => {
      const plans = service.selectStrategy(makeStaticResult());
      expect(plans).toHaveLength(1);
      expect(plans[0].strategy).toBe(DetonationStrategy.PASSIVE_TRIGGER);
      expect(plans[0].targetUrls).toContain('https://www.google.com');
    });

    it('should return DIRECT_NAVIGATION for Level 1 public domains', () => {
      const result = makeStaticResult({
        discoveredDomains: [
          {
            domain: 'youtube.com',
            source: 'code',
            context: 'YouTube API',
            platformLevel: PlatformLevel.LEVEL_1_PUBLIC,
            category: 'public',
          },
        ],
      });

      const plans = service.selectStrategy(result);
      const directPlan = plans.find(
        (p) => p.strategy === DetonationStrategy.DIRECT_NAVIGATION,
      );
      expect(directPlan).toBeDefined();
      expect(directPlan!.targetUrls[0]).toContain('youtube.com');
    });

    it('should return PASSIVE_TRIGGER for Level 2 without storage state', () => {
      const result = makeStaticResult({
        discoveredDomains: [
          {
            domain: 'facebook.com',
            source: 'code',
            context: 'FB graph API',
            platformLevel: PlatformLevel.LEVEL_2_HONEYPOT,
            category: 'social',
          },
        ],
      });

      const plans = service.selectStrategy(result);
      const passivePlan = plans.find(
        (p) => p.strategy === DetonationStrategy.PASSIVE_TRIGGER,
      );
      expect(passivePlan).toBeDefined();
    });

    it('should return PASSIVE_TRIGGER + DOM_FALSIFICATION for Level 3 with selectors', () => {
      const result = makeStaticResult({
        discoveredDomains: [
          {
            domain: 'bancolombia.com',
            source: 'code',
            context: 'banking',
            platformLevel: PlatformLevel.LEVEL_3_RESTRICTED,
            category: 'banking',
          },
        ],
        domSelectors: [
          {
            selector: '#account-balance',
            method: 'document.querySelector',
            file: 'inject.js',
            line: 10,
          },
        ],
      });

      const plans = service.selectStrategy(result);
      const domPlan = plans.find(
        (p) => p.strategy === DetonationStrategy.DOM_FALSIFICATION,
      );
      expect(domPlan).toBeDefined();
      expect(domPlan!.fakeHtmlContent).toBeDefined();
    });

    it('should handle multiple domain levels simultaneously', () => {
      const result = makeStaticResult({
        discoveredDomains: [
          {
            domain: 'youtube.com',
            source: 'code',
            context: 'yt',
            platformLevel: PlatformLevel.LEVEL_1_PUBLIC,
            category: 'public',
          },
          {
            domain: 'bancolombia.com',
            source: 'code',
            context: 'bank',
            platformLevel: PlatformLevel.LEVEL_3_RESTRICTED,
            category: 'banking',
          },
        ],
      });

      const plans = service.selectStrategy(result);
      expect(plans.length).toBeGreaterThanOrEqual(2);
    });
  });

  describe('buildFakeHtml', () => {
    it('should generate HTML with ID selectors', () => {
      const html = service.buildFakeHtml('bank.com', [
        {
          selector: '#account-balance',
          method: 'document.querySelector',
          file: 'inject.js',
          line: 1,
        },
      ]);
      expect(html).toContain('id="account-balance"');
      expect(html).toContain('bank.com');
    });

    it('should generate HTML with class selectors', () => {
      const html = service.buildFakeHtml('bank.com', [
        {
          selector: '.user-data',
          method: 'document.querySelector',
          file: 'inject.js',
          line: 1,
        },
      ]);
      expect(html).toContain('class="user-data"');
    });

    it('should generate HTML with name selectors', () => {
      const html = service.buildFakeHtml('bank.com', [
        {
          selector: 'input[name="cardNumber"]',
          method: 'document.querySelector',
          file: 'inject.js',
          line: 1,
        },
      ]);
      expect(html).toContain('name="cardNumber"');
    });

    it('should include login form with honeypot credentials', () => {
      const html = service.buildFakeHtml('bank.com', []);
      expect(html).toContain('type="password"');
      expect(html).toContain('honeypot-password-123');
      expect(html).toContain('testuser@example.com');
    });
  });
});
