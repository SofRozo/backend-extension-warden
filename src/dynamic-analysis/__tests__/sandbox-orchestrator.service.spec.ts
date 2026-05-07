import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { SandboxOrchestratorService } from '../orchestrator/sandbox-orchestrator.service.js';
import { NetworkInterceptorService, EvidenceCollector } from '../network-interceptor/network-interceptor.service.js';
import { DetonationStrategyService } from '../detonation-strategies/detonation-strategy.service.js';
import { IntelligentNavigatorService } from '../navigator/intelligent-navigator.service.js';
import { StagehandService } from '../navigator/stagehand.service.js';
import { StructuredLogger } from '../../common/logger/logger.service.js';
import { DetonationStrategy, PlatformLevel } from '../../common/enums/risk-level.enum.js';

// Mock playwright to avoid needing it installed
jest.mock('playwright', () => ({
  chromium: {
    launchPersistentContext: jest.fn().mockRejectedValue(
      new Error('Browser not available in test'),
    ),
  },
}));

describe('SandboxOrchestratorService', () => {
  let service: SandboxOrchestratorService;
  let mockDetonationStrategy: jest.Mocked<DetonationStrategyService>;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        SandboxOrchestratorService,
        NetworkInterceptorService,
        StructuredLogger,
        {
          provide: DetonationStrategyService,
          useValue: {
            selectStrategy: jest.fn().mockReturnValue([
              {
                strategy: DetonationStrategy.PASSIVE_TRIGGER,
                targetUrls: ['https://www.google.com'],
                waitTimeMs: 1000,
              },
            ]),
          },
        },
        {
          provide: ConfigService,
          useValue: {
            get: jest.fn((key: string) => {
              if (key === 'analysis.dynamicTimeoutMs') return 5000;
              return undefined;
            }),
          },
        },
        {
          provide: IntelligentNavigatorService,
          useValue: { navigateDomain: jest.fn().mockResolvedValue({ domain: '', url: '', observations: [], actionsPerformed: [], requestsToThisDomain: 0, domModificationsDetected: false, credentialsSubmitted: false }) },
        },
        {
          provide: StagehandService,
          useValue: { navigateDomain: jest.fn().mockResolvedValue({ domain: '', url: '', observations: [], actionsPerformed: [], requestsToThisDomain: 0, domModificationsDetected: false, credentialsSubmitted: false }) },
        },
      ],
    }).compile();

    service = module.get<SandboxOrchestratorService>(SandboxOrchestratorService);
    mockDetonationStrategy = module.get(DetonationStrategyService);
  });

  describe('executeDynamicAnalysis', () => {
    const staticResult = {
      findings: [],
      discoveredDomains: [],
      domSelectors: [],
      manifestPermissions: [],
      manifestHostPermissions: [],
      crxHash: 'hash',
      obfuscationDetected: false,
      deobfuscationApplied: false,
    };

    it('should call detonation strategy service', async () => {
      const result = await service.executeDynamicAnalysis(
        '/tmp/ext', 'ext-id', staticResult, 'job-1',
      );

      expect(mockDetonationStrategy.selectStrategy).toHaveBeenCalledWith(staticResult);
      expect(result).toBeDefined();
      expect(result.evidence).toBeDefined();
      expect(result.duration).toBeGreaterThanOrEqual(0);
    });

    it('should return evidence even when browser fails', async () => {
      const result = await service.executeDynamicAnalysis(
        '/tmp/ext', 'ext-id', staticResult, 'job-1',
      );

      expect(result.evidence.networkRequests).toEqual([]);
      expect(result.evidence.domMutations).toEqual([]);
      expect(result.evidence.keyboardEvents).toEqual([]);
    });

    it('should use primary strategy from first plan', async () => {
      mockDetonationStrategy.selectStrategy.mockReturnValue([
        {
          strategy: DetonationStrategy.DOM_FALSIFICATION,
          targetUrls: [],
          fakeHtmlContent: '<html></html>',
          waitTimeMs: 1000,
        },
      ]);

      const result = await service.executeDynamicAnalysis(
        '/tmp/ext', 'ext-id', staticResult, 'job-1',
      );

      expect(result.strategy).toBe(DetonationStrategy.DOM_FALSIFICATION);
    });

    it('should default to PASSIVE_TRIGGER when no plans', async () => {
      mockDetonationStrategy.selectStrategy.mockReturnValue([]);

      const result = await service.executeDynamicAnalysis(
        '/tmp/ext', 'ext-id', staticResult, 'job-1',
      );

      expect(result.strategy).toBe(DetonationStrategy.PASSIVE_TRIGGER);
    });
  });
});
