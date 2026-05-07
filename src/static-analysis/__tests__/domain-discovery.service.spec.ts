import { Test, TestingModule } from '@nestjs/testing';
import { DomainDiscoveryService } from '../domain-discovery/domain-discovery.service.js';
import { StructuredLogger } from '../../common/logger/logger.service.js';
import { PlatformLevel } from '../../common/enums/risk-level.enum.js';

describe('DomainDiscoveryService', () => {
  let service: DomainDiscoveryService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [DomainDiscoveryService, StructuredLogger],
    }).compile();

    service = module.get<DomainDiscoveryService>(DomainDiscoveryService);
  });

  describe('extractDomainsFromCode', () => {
    it('should extract hardcoded URL', () => {
      const code = `var endpoint = 'https://evil-collector.com/steal';`;
      const domains = service.extractDomainsFromCode(code, 'inject.js');
      const found = domains.find(d => d.domain === 'evil-collector.com');
      expect(found).toBeDefined();
      expect(found!.source).toBe('code');
    });

    it('should classify banking domains as Level 3', () => {
      const code = `fetch('https://www.bancolombia.com/transfers');`;
      const domains = service.extractDomainsFromCode(code, 'inject.js');
      const banking = domains.find(d => d.domain.includes('bancolombia'));
      expect(banking).toBeDefined();
      expect(banking!.platformLevel).toBe(PlatformLevel.LEVEL_3_RESTRICTED);
      expect(banking!.category).toBe('banking');
    });

    it('should classify government domains as Level 3', () => {
      const code = `var taxPortal = 'https://dian.gov.co/portales';`;
      const domains = service.extractDomainsFromCode(code, 'bg.js');
      const gov = domains.find(d => d.domain.includes('dian.gov'));
      expect(gov).toBeDefined();
      expect(gov!.platformLevel).toBe(PlatformLevel.LEVEL_3_RESTRICTED);
    });

    it('should classify social media as Level 2', () => {
      const code = `var api = 'https://graph.facebook.com/v18.0/me';`;
      const domains = service.extractDomainsFromCode(code, 'social.js');
      const fb = domains.find(d => d.domain.includes('facebook'));
      expect(fb).toBeDefined();
      expect(fb!.platformLevel).toBe(PlatformLevel.LEVEL_2_HONEYPOT);
    });

    it('should classify YouTube as Level 1', () => {
      const code = `var yt = 'https://www.youtube.com/api/v3/videos';`;
      const domains = service.extractDomainsFromCode(code, 'yt.js');
      const youtube = domains.find(d => d.domain.includes('youtube'));
      expect(youtube).toBeDefined();
      expect(youtube!.platformLevel).toBe(PlatformLevel.LEVEL_1_PUBLIC);
    });

    it('should extract domain from string literal', () => {
      const code = `var host = 'malicious-bank.com';`;
      const domains = service.extractDomainsFromCode(code, 'bg.js');
      const found = domains.find(d => d.domain === 'malicious-bank.com');
      expect(found).toBeDefined();
    });

    it('should not extract CDN domains as suspicious', () => {
      const code = `var cdn = 'https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js';`;
      const domains = service.extractDomainsFromCode(code, 'bg.js');
      // CDNs should be filtered
      const cdnFound = domains.find(d => d.domain === 'cdnjs.cloudflare.com');
      expect(cdnFound).toBeUndefined();
    });

    it('should extract multiple domains from template literals', () => {
      const code = `
        const endpoint = \`https://tracking.evil.com/\${userId}\`;
        const backup = \`https://backup.evil.com/collect\`;
      `;
      const domains = service.extractDomainsFromCode(code, 'track.js');
      expect(domains.length).toBeGreaterThanOrEqual(1);
    });

    it('should handle empty code', () => {
      const domains = service.extractDomainsFromCode('', 'empty.js');
      expect(domains).toEqual([]);
    });
  });

  describe('extractDomainsFromManifest', () => {
    it('should extract domains from host_permissions', () => {
      const manifest = {
        host_permissions: ['https://www.bancolombia.com/*', 'https://gmail.com/*'],
      };
      const domains = service.extractDomainsFromManifest(manifest);
      expect(domains.some(d => d.domain === 'www.bancolombia.com')).toBe(true);
      expect(domains.some(d => d.domain === 'gmail.com')).toBe(true);
    });

    it('should extract domains from content_scripts.matches', () => {
      const manifest = {
        content_scripts: [
          { matches: ['https://www.paypal.com/*', '*://mail.google.com/*'] },
        ],
      };
      const domains = service.extractDomainsFromManifest(manifest);
      expect(domains.some(d => d.domain.includes('paypal'))).toBe(true);
    });

    it('should mark manifest domains with source=manifest', () => {
      const manifest = { host_permissions: ['https://instagram.com/*'] };
      const domains = service.extractDomainsFromManifest(manifest);
      domains.forEach(d => expect(d.source).toBe('manifest'));
    });
  });

  describe('classifyDomain', () => {
    it('should classify .edu as educational Level 3', () => {
      const result = service.classifyDomain('university.edu');
      expect(result.level).toBe(PlatformLevel.LEVEL_3_RESTRICTED);
      expect(result.category).toBe('educational');
    });

    it('should classify PayPal as financial Level 3', () => {
      const result = service.classifyDomain('paypal.com');
      expect(result.level).toBe(PlatformLevel.LEVEL_3_RESTRICTED);
    });

    it('should classify unknown domains as Level 1 by default', () => {
      const result = service.classifyDomain('random-website.com');
      expect(result.level).toBe(PlatformLevel.LEVEL_1_PUBLIC);
    });
  });
});
