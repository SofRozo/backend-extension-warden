import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { ThreatIntelService } from '../threat-intel.service.js';
import { StructuredLogger } from '../../common/logger/logger.service.js';
import axios from 'axios';

jest.mock('axios');
const mockedAxios = axios as jest.Mocked<typeof axios>;

describe('ThreatIntelService', () => {
  let service: ThreatIntelService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        ThreatIntelService,
        StructuredLogger,
        {
          provide: ConfigService,
          useValue: {
            get: jest.fn((key: string) => {
              const config: Record<string, any> = {
                'threatIntel.virusTotalApiKey': 'test-vt-key',
                'threatIntel.urlScanApiKey': 'test-urlscan-key',
                'threatIntel.abuseIpdbApiKey': null,
                'threatIntel.timeoutMs': 5000,
                'threatIntel.cacheTtlSeconds': 3600,
              };
              return config[key];
            }),
          },
        },
      ],
    }).compile();

    service = module.get<ThreatIntelService>(ThreatIntelService);
    jest.clearAllMocks();
  });

  describe('queryDomain', () => {
    it('should query VirusTotal and return results', async () => {
      mockedAxios.get.mockResolvedValueOnce({
        data: {
          data: {
            attributes: {
              last_analysis_stats: {
                malicious: 5,
                suspicious: 2,
                harmless: 60,
                undetected: 10,
              },
              categories: { cat1: 'phishing' },
              reputation: -15,
            },
          },
        },
      }).mockResolvedValueOnce({
        data: { results: [] },
      });

      const results = await service.queryDomain('evil.com', 'job-1');
      const vtResult = results.find(r => r.provider === 'virustotal');
      expect(vtResult).toBeDefined();
      expect(vtResult!.isMalicious).toBe(true);
      expect(vtResult!.score).toBeGreaterThan(0);
    });

    it('should return cached results on second call', async () => {
      mockedAxios.get.mockResolvedValueOnce({
        data: {
          data: {
            attributes: {
              last_analysis_stats: { malicious: 0, suspicious: 0, harmless: 70, undetected: 5 },
              categories: {},
            },
          },
        },
      }).mockResolvedValueOnce({
        data: { results: [] },
      });

      await service.queryDomain('cached-domain.com', 'job-1');
      mockedAxios.get.mockClear();

      const results2 = await service.queryDomain('cached-domain.com', 'job-2');
      expect(mockedAxios.get).not.toHaveBeenCalled();
      expect(results2).toBeDefined();
    });

    it('should handle API errors gracefully', async () => {
      mockedAxios.get.mockRejectedValue(new Error('Network error'));

      const results = await service.queryDomain('fail.com', 'job-1');
      expect(results).toEqual([]);
    });

    it('should mark domain as not malicious when score is 0', async () => {
      mockedAxios.get.mockResolvedValueOnce({
        data: {
          data: {
            attributes: {
              last_analysis_stats: { malicious: 0, suspicious: 0, harmless: 80, undetected: 0 },
              categories: {},
            },
          },
        },
      }).mockResolvedValueOnce({
        data: { results: [] },
      });

      const results = await service.queryDomain('safe.com', 'job-1');
      const vtResult = results.find(r => r.provider === 'virustotal');
      expect(vtResult?.isMalicious).toBe(false);
    });
  });

  describe('queryDomains', () => {
    it('should deduplicate domains', async () => {
      mockedAxios.get.mockResolvedValue({
        data: { data: { attributes: { last_analysis_stats: {}, categories: {} } }, results: [] },
      });

      await service.queryDomains(['a.com', 'a.com', 'b.com'], 'job-1');
      // Should only query unique domains (a.com and b.com)
      // Each domain triggers 2 API calls (VT + URLScan), AbuseIPDB skipped (no key)
      expect(mockedAxios.get.mock.calls.length).toBeLessThanOrEqual(4);
    });

    it('should handle empty domain list', async () => {
      const results = await service.queryDomains([], 'job-1');
      expect(results).toEqual([]);
    });
  });
});
