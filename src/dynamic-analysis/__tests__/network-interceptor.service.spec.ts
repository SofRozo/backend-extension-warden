import { Test, TestingModule } from '@nestjs/testing';
import {
  NetworkInterceptorService,
  EvidenceCollector,
} from '../network-interceptor/network-interceptor.service.js';
import { StructuredLogger } from '../../common/logger/logger.service.js';

describe('NetworkInterceptorService', () => {
  let service: NetworkInterceptorService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [NetworkInterceptorService, StructuredLogger],
    }).compile();

    service = module.get<NetworkInterceptorService>(NetworkInterceptorService);
  });

  it('should create an EvidenceCollector', () => {
    const collector = service.createEvidenceCollector('ext-123');
    expect(collector).toBeInstanceOf(EvidenceCollector);
  });
});

describe('EvidenceCollector', () => {
  let collector: EvidenceCollector;

  beforeEach(() => {
    const logger = new StructuredLogger();
    collector = new EvidenceCollector('test-ext-id', logger);
  });

  describe('onNetworkRequest', () => {
    it('should record network requests', () => {
      collector.onNetworkRequest(
        'https://evil.com/collect',
        'POST',
        { 'Content-Type': 'application/json' },
        '{"data":"stolen"}',
        undefined,
      );

      const evidence = collector.getEvidence();
      expect(evidence.networkRequests).toHaveLength(1);
      expect(evidence.networkRequests[0].url).toBe('https://evil.com/collect');
      expect(evidence.networkRequests[0].method).toBe('POST');
    });

    it('should classify chrome-extension:// URLs as extension origin', () => {
      collector.onNetworkRequest(
        'chrome-extension://test-ext-id/bg.js',
        'GET',
        {},
        undefined,
        undefined,
      );

      const evidence = collector.getEvidence();
      expect(evidence.networkRequests[0].origin).toBe('extension');
    });

    it('should classify requests from extension initiator as extension origin', () => {
      collector.onNetworkRequest(
        'https://api.example.com/data',
        'POST',
        {},
        undefined,
        'chrome-extension://test-ext-id',
      );

      const evidence = collector.getEvidence();
      expect(evidence.networkRequests[0].origin).toBe('extension');
    });

    it('should classify Chrome internal URLs as browser origin', () => {
      collector.onNetworkRequest(
        'https://clients2.google.com/service/update2',
        'GET',
        {},
        undefined,
        undefined,
      );

      const evidence = collector.getEvidence();
      expect(evidence.networkRequests[0].origin).toBe('browser');
    });

    it('should classify unknown URLs as unknown origin', () => {
      collector.onNetworkRequest(
        'https://random-site.com/page',
        'GET',
        {},
        undefined,
        undefined,
      );

      const evidence = collector.getEvidence();
      expect(evidence.networkRequests[0].origin).toBe('unknown');
    });

    it('should truncate request body to 5000 chars', () => {
      const longBody = 'x'.repeat(10000);
      collector.onNetworkRequest(
        'https://a.com',
        'POST',
        {},
        longBody,
        undefined,
      );

      const evidence = collector.getEvidence();
      expect(evidence.networkRequests[0].body!.length).toBe(5000);
    });
  });

  describe('onDomMutation', () => {
    it('should record DOM mutations', () => {
      collector.onDomMutation(
        'childList',
        'DIV#login-form',
        '<script>alert(1)</script>',
      );

      const evidence = collector.getEvidence();
      expect(evidence.domMutations).toHaveLength(1);
      expect(evidence.domMutations[0].type).toBe('childList');
      expect(evidence.domMutations[0].target).toBe('DIV#login-form');
    });

    it('should truncate mutation value to 1000 chars', () => {
      const longValue = 'y'.repeat(5000);
      collector.onDomMutation('characterData', 'SPAN', longValue);

      const evidence = collector.getEvidence();
      expect(evidence.domMutations[0].value!.length).toBe(1000);
    });
  });

  describe('onKeyboardEvent', () => {
    it('should record keyboard events', () => {
      collector.onKeyboardEvent('keydown', 'a', 'INPUT#password');

      const evidence = collector.getEvidence();
      expect(evidence.keyboardEvents).toHaveLength(1);
      expect(evidence.keyboardEvents[0].key).toBe('a');
      expect(evidence.keyboardEvents[0].target).toBe('INPUT#password');
    });
  });

  describe('getExtensionRequests', () => {
    it('should filter only extension-originated requests', () => {
      collector.onNetworkRequest(
        'chrome-extension://ext/bg.js',
        'GET',
        {},
        undefined,
        undefined,
      );
      collector.onNetworkRequest(
        'https://google.com',
        'GET',
        {},
        undefined,
        undefined,
      );
      collector.onNetworkRequest(
        'https://api.evil.com',
        'POST',
        {},
        undefined,
        'chrome-extension://ext',
      );

      const extRequests = collector.getExtensionRequests();
      expect(extRequests).toHaveLength(2);
    });
  });

  describe('getEvidence', () => {
    it('should return empty evidence when nothing recorded', () => {
      const evidence = collector.getEvidence();
      expect(evidence.networkRequests).toEqual([]);
      expect(evidence.domMutations).toEqual([]);
      expect(evidence.keyboardEvents).toEqual([]);
    });
  });
});
