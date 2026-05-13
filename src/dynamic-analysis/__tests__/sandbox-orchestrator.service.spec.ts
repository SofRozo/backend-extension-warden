import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { SandboxOrchestratorService } from '../orchestrator/sandbox-orchestrator.service.js';
import { NetworkInterceptorService } from '../network-interceptor/network-interceptor.service.js';
import { IntelligentNavigatorService } from '../navigator/intelligent-navigator.service.js';
import { StagehandService } from '../navigator/stagehand.service.js';
import { StructuredLogger } from '../../common/logger/logger.service.js';
import { DetonationStrategy } from '../../common/enums/risk-level.enum.js';
import type { DomainFinding } from '../../common/interfaces/analysis.interfaces.js';

jest.mock('playwright', () => ({
  chromium: {
    launchPersistentContext: jest
      .fn()
      .mockRejectedValue(new Error('Browser not available in test')),
  },
}));

describe('SandboxOrchestratorService', () => {
  let service: SandboxOrchestratorService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        SandboxOrchestratorService,
        NetworkInterceptorService,
        StructuredLogger,
        {
          provide: ConfigService,
          useValue: {
            get: jest.fn((key: string) => {
              if (key === 'analysis.dynamicTimeoutMs') return 30000;
              if (key === 'analysis.useStagehand') return false;
              return undefined;
            }),
          },
        },
        {
          provide: IntelligentNavigatorService,
          useValue: { navigateDomain: jest.fn() },
        },
        {
          provide: StagehandService,
          useValue: { navigateDomain: jest.fn() },
        },
      ],
    }).compile();

    service = module.get<SandboxOrchestratorService>(
      SandboxOrchestratorService,
    );
  });

  it('returns empty result when there are no priority findings', async () => {
    const result = await service.executeDynamicAnalysis(
      '/tmp/ext',
      'ext-id',
      [],
      'propósito',
      'job-1',
    );

    expect(result.strategy).toBe(DetonationStrategy.DIRECT_NAVIGATION);
    expect(result.domainObservations).toEqual([]);
    expect(result.timedOut).toBe(false);
  });

  it('returns observations array (empty when browser fails to launch)', async () => {
    const findings: DomainFinding[] = [
      {
        fileType: 'background',
        filePath: 'src/bg.js',
        discoveryType: 'url_en_codigo',
        domain: 'instagram.com',
        category: 'sensible_redes_sociales',
        priority: 5,
        line: 10,
      },
    ];

    const result = await service.executeDynamicAnalysis(
      '/tmp/ext',
      'ext-id',
      findings,
      'propósito',
      'job-2',
    );

    expect(result.strategy).toBe(DetonationStrategy.DIRECT_NAVIGATION);
    expect(Array.isArray(result.domainObservations)).toBe(true);
  });
});
