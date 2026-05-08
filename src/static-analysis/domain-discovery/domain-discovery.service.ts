import { Injectable } from '@nestjs/common';
import * as parser from '@babel/parser';
import _traverse from '@babel/traverse';
import { DiscoveredDomain } from '../../common/interfaces/analysis.interfaces.js';
import { PlatformLevel } from '../../common/enums/risk-level.enum.js';
import { StructuredLogger } from '../../common/logger/logger.service.js';

const traverse =
  typeof _traverse === 'function'
    ? _traverse
    : (_traverse as unknown as { default: typeof _traverse }).default;

const RESTRICTED_PLATFORM_PATTERNS: {
  pattern: RegExp;
  category: string;
  level: PlatformLevel;
}[] = [
  // Banking / Financial
  {
    pattern: /bancolombia|davivienda|bbva|nequi/i,
    category: 'banking',
    level: PlatformLevel.LEVEL_3_RESTRICTED,
  },
  {
    pattern: /chase\.com|bankofamerica|wellsfargo|citibank/i,
    category: 'banking',
    level: PlatformLevel.LEVEL_3_RESTRICTED,
  },
  {
    pattern: /paypal\.com|stripe\.com|mercadopago/i,
    category: 'financial',
    level: PlatformLevel.LEVEL_3_RESTRICTED,
  },
  {
    pattern: /nubank|nu\.com\.co/i,
    category: 'banking',
    level: PlatformLevel.LEVEL_3_RESTRICTED,
  },
  // Educational
  {
    pattern: /moodle|canvas|blackboard|brightspace/i,
    category: 'educational',
    level: PlatformLevel.LEVEL_3_RESTRICTED,
  },
  {
    pattern: /\.edu(\.[a-z]{2})?$/i,
    category: 'educational',
    level: PlatformLevel.LEVEL_3_RESTRICTED,
  },
  // Government
  {
    pattern: /\.gov(\.[a-z]{2})?$/i,
    category: 'government',
    level: PlatformLevel.LEVEL_3_RESTRICTED,
  },
  {
    pattern: /dian\.gov|registraduria|sisben/i,
    category: 'government',
    level: PlatformLevel.LEVEL_3_RESTRICTED,
  },
  // Health
  {
    pattern: /\.health|hospital|medic|salud|eps\./i,
    category: 'health',
    level: PlatformLevel.LEVEL_3_RESTRICTED,
  },
  // Public platforms (Level 1)
  {
    pattern: /youtube\.com|wikipedia\.org|reddit\.com/i,
    category: 'public',
    level: PlatformLevel.LEVEL_1_PUBLIC,
  },
  {
    pattern: /news\.ycombinator|medium\.com|stackoverflow/i,
    category: 'public',
    level: PlatformLevel.LEVEL_1_PUBLIC,
  },
  // Social media (Level 2 - honeypot possible)
  {
    pattern: /facebook\.com|fb\.com|instagram\.com/i,
    category: 'social',
    level: PlatformLevel.LEVEL_2_HONEYPOT,
  },
  {
    pattern: /twitter\.com|x\.com|linkedin\.com/i,
    category: 'social',
    level: PlatformLevel.LEVEL_2_HONEYPOT,
  },
  {
    pattern: /gmail\.com|mail\.google\.com|outlook\.com/i,
    category: 'email',
    level: PlatformLevel.LEVEL_2_HONEYPOT,
  },
];

@Injectable()
export class DomainDiscoveryService {
  constructor(private readonly logger: StructuredLogger) {}

  extractDomainsFromCode(code: string, filename: string): DiscoveredDomain[] {
    const domains: DiscoveredDomain[] = [];
    const seen = new Set<string>();

    // Method 1: Regex extraction — strip comments first so URLs inside /* */ or // don't create false positives
    this.extractDomainsRegex(this.stripComments(code), filename, domains, seen);

    // Method 2: AST-based string literal extraction
    this.extractDomainsFromAst(code, filename, domains, seen);

    return domains;
  }

  extractDomainsFromManifest(
    manifest: Record<string, unknown>,
  ): DiscoveredDomain[] {
    const domains: DiscoveredDomain[] = [];
    const seen = new Set<string>();

    // host_permissions
    const hostPerms =
      (manifest.host_permissions as string[]) ||
      (manifest.permissions as string[]) ||
      [];
    for (const perm of hostPerms) {
      const domain = this.extractDomainFromPermission(perm);
      if (domain && !seen.has(domain)) {
        seen.add(domain);
        domains.push({
          domain,
          source: 'manifest',
          context: `host_permissions: ${perm}`,
          platformLevel: this.classifyDomain(domain).level,
          category: this.classifyDomain(domain).category,
        });
      }
    }

    // content_scripts matches
    const contentScripts =
      (manifest.content_scripts as { matches?: string[] }[]) || [];
    for (const cs of contentScripts) {
      for (const match of cs.matches || []) {
        const domain = this.extractDomainFromPermission(match);
        if (domain && !seen.has(domain)) {
          seen.add(domain);
          domains.push({
            domain,
            source: 'manifest',
            context: `content_scripts.matches: ${match}`,
            platformLevel: this.classifyDomain(domain).level,
            category: this.classifyDomain(domain).category,
          });
        }
      }
    }

    return domains;
  }

  classifyDomain(domain: string): { level: PlatformLevel; category: string } {
    for (const p of RESTRICTED_PLATFORM_PATTERNS) {
      if (p.pattern.test(domain)) {
        return { level: p.level, category: p.category };
      }
    }
    return { level: PlatformLevel.LEVEL_1_PUBLIC, category: 'unknown' };
  }

  private extractDomainsRegex(
    code: string,
    filename: string,
    domains: DiscoveredDomain[],
    seen: Set<string>,
  ): void {
    // Match URLs
    const urlRegex =
      /https?:\/\/[a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+(?:\/[^\s'"`,;)\]}>]*)?/g;
    let match: RegExpExecArray | null;
    while ((match = urlRegex.exec(code)) !== null) {
      const domain = this.extractDomainFromUrl(match[0]);
      if (domain && !seen.has(domain) && !this.isCommonCdn(domain)) {
        seen.add(domain);
        const classification = this.classifyDomain(domain);
        domains.push({
          domain,
          source: 'code',
          context: match[0].substring(0, 200),
          platformLevel: classification.level,
          category: classification.category,
        });
      }
    }

    // Match domain-like strings
    const domainRegex =
      /['"`]([a-zA-Z0-9][-a-zA-Z0-9]*\.(?:com|org|net|edu|gov|io|co|me|info|biz)(?:\.[a-z]{2,3})?)['"`]/g;
    while ((match = domainRegex.exec(code)) !== null) {
      const domain = match[1].toLowerCase();
      if (!seen.has(domain) && !this.isCommonCdn(domain)) {
        seen.add(domain);
        const classification = this.classifyDomain(domain);
        domains.push({
          domain,
          source: 'code',
          context: code.substring(
            Math.max(0, match.index - 30),
            Math.min(code.length, match.index + match[0].length + 30),
          ),
          platformLevel: classification.level,
          category: classification.category,
        });
      }
    }
  }

  private extractDomainsFromAst(
    code: string,
    filename: string,
    domains: DiscoveredDomain[],
    seen: Set<string>,
  ): void {
    let ast: ReturnType<typeof parser.parse>;
    try {
      ast = parser.parse(code, {
        sourceType: 'unambiguous',
        plugins: ['dynamicImport', 'optionalChaining'],
        errorRecovery: true,
      });
    } catch {
      return;
    }

    try {
      traverse(ast, {
        StringLiteral: (nodePath) => {
          const value = nodePath.node.value;
          if (value.length < 5 || value.length > 2000) return;

          const domain =
            this.extractDomainFromUrl(value) ||
            (this.looksLikeDomain(value) ? value.toLowerCase() : null);

          if (domain && !seen.has(domain) && !this.isCommonCdn(domain)) {
            seen.add(domain);
            const classification = this.classifyDomain(domain);
            domains.push({
              domain,
              source: 'code',
              context: value.substring(0, 200),
              platformLevel: classification.level,
              category: classification.category,
            });
          }
        },
        TemplateLiteral: (nodePath) => {
          for (const quasi of nodePath.node.quasis) {
            const value = quasi.value.cooked || quasi.value.raw;
            if (!value || value.length < 5) continue;
            const domain = this.extractDomainFromUrl(value);
            if (domain && !seen.has(domain) && !this.isCommonCdn(domain)) {
              seen.add(domain);
              const classification = this.classifyDomain(domain);
              domains.push({
                domain,
                source: 'code',
                context: value.substring(0, 200),
                platformLevel: classification.level,
                category: classification.category,
              });
            }
          }
        },
      });
    } catch {
      // Best effort
    }
  }

  private extractDomainFromUrl(url: string): string | null {
    try {
      const parsed = new URL(url);
      return parsed.hostname.toLowerCase();
    } catch {
      return null;
    }
  }

  private extractDomainFromPermission(perm: string): string | null {
    const cleaned = perm.replace(/^\*:\/\//, 'https://').replace(/\/\*$/, '');
    try {
      const parsed = new URL(
        cleaned.includes('://') ? cleaned : `https://${cleaned}`,
      );
      const host = parsed.hostname.replace(/^\*\./, '');
      return host === '*' ? null : host.toLowerCase();
    } catch {
      return null;
    }
  }

  private looksLikeDomain(str: string): boolean {
    return /^[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}(\.[a-zA-Z]{2,})?$/.test(
      str,
    );
  }

  private stripComments(code: string): string {
    // Remove block comments, preserving newlines so line numbers stay accurate
    let result = code.replace(/\/\*[\s\S]*?\*\//g, (m) =>
      '\n'.repeat((m.match(/\n/g) ?? []).length),
    );
    // Remove line comments
    result = result.replace(/\/\/[^\n]*/g, '');
    return result;
  }

  private isCommonCdn(domain: string): boolean {
    const cdns = [
      'googleapis.com',
      'gstatic.com',
      'cloudflare.com',
      'cdn.jsdelivr.net',
      'unpkg.com',
      'cdnjs.cloudflare.com',
      'chrome.google.com',
      'developer.chrome.com',
    ];
    return cdns.some((cdn) => domain === cdn || domain.endsWith(`.${cdn}`));
  }
}
