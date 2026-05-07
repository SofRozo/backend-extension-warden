import { Injectable, Optional } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { EncryptionService } from '../../common/crypto/encryption.service.js';
import {
  StaticAnalysisResult,
  DiscoveredDomain,
  DomSelector,
} from '../../common/interfaces/analysis.interfaces.js';
import {
  DetonationStrategy,
  PlatformLevel,
} from '../../common/enums/risk-level.enum.js';

export interface DetonationPlan {
  strategy: DetonationStrategy;
  targetUrls: string[];
  storageStatePath?: string;
  fakeHtmlContent?: string;
  waitTimeMs: number;
}

@Injectable()
export class DetonationStrategyService {
  constructor(
    private readonly config: ConfigService,
    @Optional() private readonly encryption?: EncryptionService,
  ) { }

  selectStrategy(
    staticResult: StaticAnalysisResult,
  ): DetonationPlan[] {
    const demoMode = this.config.get<boolean>('demo.enabled') || false;
    const plans: DetonationPlan[] = [];

    // Filter out "domains" that are actually internal asset filenames the static
    // analyzer mis-extracted (e.g. "breedspritecache.js", "main.js", "heart.png").
    // Visiting those wastes the dynamic budget on bogus 404s.
    const cleanDomains = staticResult.discoveredDomains.filter((d) =>
      isLikelyRealDomain(d.domain),
    );
    const domainsByLevel = this.groupDomainsByLevel(cleanDomains);

    // ─── Hardcoded extension domains FIRST ──────────────────────────────────
    // These are the actual targets the extension was built for. They run before
    // demo plans so they always get budget — see analysis.processor for the
    // extra time grant when demo mode is on.

    // Level 3: Restricted platforms — use B strategies (most sensitive first)
    for (const domain of domainsByLevel.get(PlatformLevel.LEVEL_3_RESTRICTED) || []) {
      plans.push({
        strategy: DetonationStrategy.PASSIVE_TRIGGER,
        targetUrls: [this.getLoginUrl(domain.domain)],
        waitTimeMs: 10000,
      });

      const relevantSelectors = this.findSelectorsForDomain(
        domain,
        staticResult.domSelectors,
      );
      if (relevantSelectors.length > 0) {
        const fakeHtml = this.buildFakeHtml(domain.domain, relevantSelectors);
        plans.push({
          strategy: DetonationStrategy.DOM_FALSIFICATION,
          targetUrls: [],
          fakeHtmlContent: fakeHtml,
          waitTimeMs: 10000,
        });
      }
    }

    // Level 2: State injection with honeypot accounts
    for (const domain of domainsByLevel.get(PlatformLevel.LEVEL_2_HONEYPOT) || []) {
      const storageStatePath = this.getStorageStatePath(domain.domain);
      if (storageStatePath) {
        plans.push({
          strategy: DetonationStrategy.STATE_INJECTION,
          targetUrls: [`https://${domain.domain}`],
          storageStatePath,
          waitTimeMs: 15000,
        });
      } else {
        plans.push({
          strategy: DetonationStrategy.PASSIVE_TRIGGER,
          targetUrls: [this.getLoginUrl(domain.domain)],
          waitTimeMs: 10000,
        });
      }
    }

    // Level 1: Direct navigation (no account needed)
    for (const domain of domainsByLevel.get(PlatformLevel.LEVEL_1_PUBLIC) || []) {
      plans.push({
        strategy: DetonationStrategy.DIRECT_NAVIGATION,
        targetUrls: [`https://${domain.domain}`],
        waitTimeMs: 10000,
      });
    }

    // ─── Demo plans LAST ────────────────────────────────────────────────────
    // Fixed showcase navigation; only added in demo mode and only after the
    // real hardcoded targets so they don't starve the timeout.
    if (demoMode) {
      plans.push(...this.buildDemoPlans());
    }

    // If still no plans, generic fallback so the worker doesn't no-op.
    if (plans.length === 0) {
      plans.push({
        strategy: DetonationStrategy.PASSIVE_TRIGGER,
        targetUrls: [
          'https://www.google.com',
          'https://www.wikipedia.org',
        ],
        waitTimeMs: 10000,
      });
    }

    return plans;
  }

  // ─── Demo plans ────────────────────────────────────────────────────────────
  // Fixed sequence shown during the professor demo regardless of extension content.

  private buildDemoPlans(): DetonationPlan[] {
    const plans: DetonationPlan[] = [];

    // 1. YouTube
    plans.push({
      strategy: DetonationStrategy.STATE_INJECTION,
      targetUrls: ['https://www.youtube.com'],
      storageStatePath: this.getDemoStorageStatePath('youtube.com') ?? undefined,
      waitTimeMs: 15000,
    });

    // 2. Instagram
    plans.push({
      strategy: DetonationStrategy.STATE_INJECTION,
      targetUrls: ['https://www.instagram.com'],
      storageStatePath: this.getDemoStorageStatePath('instagram.com') ?? undefined,
      waitTimeMs: 15000,
    });

    // 3. ChatGPT
    plans.push({
      strategy: DetonationStrategy.STATE_INJECTION,
      targetUrls: ['https://chat.openai.com'],
      storageStatePath: this.getDemoStorageStatePath('chat.openai.com') ?? undefined,
      waitTimeMs: 15000,
    });

    // 4. Gmail
    plans.push({
      strategy: DetonationStrategy.STATE_INJECTION,
      targetUrls: ['https://mail.google.com'],
      storageStatePath: this.getDemoStorageStatePath('gmail.com') ?? undefined,
      waitTimeMs: 15000,
    });

    // 3. Fake login page — honey-pot with visible email + password fields
    //    and a fake account balance to provoke data-theft behavior
    plans.push({
      strategy: DetonationStrategy.DOM_FALSIFICATION,
      targetUrls: [],
      fakeHtmlContent: this.buildDemoFakeHtml(),
      waitTimeMs: 12000,
    });

    return plans;
  }

  // ─── HTML builders ─────────────────────────────────────────────────────────

  buildFakeHtml(
    domain: string,
    selectors: DomSelector[],
  ): string {
    const elements = selectors.map((s) => {
      const sel = s.selector;
      if (sel.startsWith('#')) {
        return `<div id="${sel.substring(1)}"><input type="text" value="test-data" /><button>Submit</button></div>`;
      }
      if (sel.startsWith('.')) {
        return `<div class="${sel.substring(1)}"><input type="text" value="test-data" /><button>Submit</button></div>`;
      }
      if (sel.includes('[name=')) {
        const nameMatch = sel.match(/\[name=["']?([^"'\]]+)/);
        if (nameMatch) {
          return `<input type="text" name="${nameMatch[1]}" value="test-data" />`;
        }
      }
      if (sel.includes('input[type="password"]') || sel.includes("input[type='password']")) {
        return `<input type="password" value="honeypot-password-123" />`;
      }
      return `<div data-selector="${sel}"><input type="text" value="test-data" /></div>`;
    });

    return `<!DOCTYPE html>
<html>
<head><title>${domain} - Login</title></head>
<body>
  <h1>Welcome to ${domain}</h1>
  <form id="login-form" action="/login" method="POST">
    <input type="text" name="username" id="username" value="testuser@example.com" />
    <input type="password" name="password" id="password" value="honeypot-password-123" />
    ${elements.join('\n    ')}
    <button type="submit" id="btn-submit">Sign In</button>
  </form>
  <div id="account-info">
    <span class="user-name">Test User</span>
    <span class="user-email">testuser@example.com</span>
    <span class="balance">$10,000.00</span>
  </div>
</body>
</html>`;
  }

  private buildDemoFakeHtml(): string {
    return `<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <title>BancoDemo - Iniciar Sesión</title>
  <style>
    body { font-family: Arial, sans-serif; background: #f0f2f5; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
    .card { background: white; padding: 32px; border-radius: 12px; box-shadow: 0 2px 16px rgba(0,0,0,.12); width: 360px; }
    h2 { color: #1a3c6e; margin-top: 0; }
    label { display: block; font-size: 13px; color: #555; margin-bottom: 4px; margin-top: 16px; }
    input[type=text], input[type=email], input[type=password] { width: 100%; padding: 10px; border: 1px solid #ccc; border-radius: 6px; box-sizing: border-box; font-size: 14px; }
    button { width: 100%; padding: 12px; background: #1a3c6e; color: white; border: none; border-radius: 6px; font-size: 15px; cursor: pointer; margin-top: 24px; }
    .info { background: #f8f9fa; border-radius: 8px; padding: 12px; margin-top: 20px; font-size: 13px; color: #444; }
  </style>
</head>
<body>
  <div class="card">
    <h2>🏦 BancoDemo</h2>
    <form id="login-form" action="https://bancologin.honeypot.internal/auth" method="POST">
      <label for="email">Correo electrónico</label>
      <input type="email" id="email" name="email" value="sofia.rozo@bancodemo.co" autocomplete="email" />

      <label for="password">Contraseña</label>
      <input type="password" id="password" name="password" value="Tesis2025!Segura" autocomplete="current-password" />

      <label for="account">Número de cuenta</label>
      <input type="text" id="account" name="account_number" value="5423-8801-0042-9917" />

      <button type="submit" id="btn-login">Iniciar sesión</button>
    </form>

    <div class="info">
      <strong>Saldo disponible:</strong> $24.850.000 COP<br>
      <strong>Último acceso:</strong> Hoy, 09:14 a.m.<br>
      <strong>Token sesión:</strong> eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.demo
    </div>
  </div>
</body>
</html>`;
  }

  // ─── Storage state helpers ─────────────────────────────────────────────────

  private getDemoStorageStatePath(domain: string): string | undefined {
    // Try configured path first, then well-known fallbacks. This lets the same
    // .env (DEMO_STORAGE_STATE_PATH=/data/honeypot/states) keep working in
    // Docker while a Windows-native worker can still find the same files at
    // ./data/honeypot/states relative to the project root.
    const configured = this.config.get<string>('demo.storageStatePath');
    const candidates = [
      configured,
      './data/honeypot/states',
      './demo-states',
    ].filter((p): p is string => !!p);

    try {
      const fs = require('fs');
      const path = require('path');
      for (const base of candidates) {
        const statePath = path.join(base, `${domain}.json`);
        if (fs.existsSync(statePath)) return statePath;
      }
    } catch {
      // fs not available
    }
    return undefined;
  }

  private getStorageStatePath(domain: string): string | undefined {
    const basePath =
      this.config.get<string>('honeypot.storageStatePath') ||
      '/data/honeypot/states';
    const encryptedPath = `${basePath}/${domain.replace(/\./g, '_')}.enc`;
    const plaintextFallback = `${basePath}/${domain.replace(/\./g, '_')}.json`;

    try {
      const fs = require('fs');
      if (fs.existsSync(encryptedPath) && this.encryption) {
        const decrypted = this.encryption.loadAndDecryptState(encryptedPath);
        const tmpPath = `/tmp/ext-sandbox/${domain.replace(/\./g, '_')}_state.json`;
        fs.writeFileSync(tmpPath, JSON.stringify(decrypted));
        return tmpPath;
      }
      if (fs.existsSync(plaintextFallback)) return plaintextFallback;
    } catch {
      // No account available
    }
    return undefined;
  }

  // ─── Utilities ─────────────────────────────────────────────────────────────

  private groupDomainsByLevel(
    domains: DiscoveredDomain[],
  ): Map<PlatformLevel, DiscoveredDomain[]> {
    const map = new Map<PlatformLevel, DiscoveredDomain[]>();
    for (const domain of domains) {
      const list = map.get(domain.platformLevel) || [];
      list.push(domain);
      map.set(domain.platformLevel, list);
    }
    return map;
  }

  private getLoginUrl(domain: string): string {
    const loginPaths: Record<string, string> = {
      'instagram.com': 'https://www.instagram.com/accounts/login/',
      'gmail.com': 'https://mail.google.com/',
      'mail.google.com': 'https://mail.google.com/',
      'youtube.com': 'https://www.youtube.com/',
      'chatgpt.com': 'https://chatgpt.com/auth/login',
      'chat.openai.com': 'https://chat.openai.com/auth/login',
    };

    return loginPaths[domain] || `https://${domain}/login`;
  }

  private findSelectorsForDomain(
    _domain: DiscoveredDomain,
    selectors: DomSelector[],
  ): DomSelector[] {
    return selectors;
  }
}

/**
 * Reject "domains" that are actually internal extension asset filenames the
 * static analyzer mis-extracted (e.g. "main.js", "breedspritecache.js",
 * "heart.png"), or other strings that would never resolve to a real host.
 */
export function isLikelyRealDomain(domain: string): boolean {
  if (!domain || typeof domain !== 'string') return false;
  const d = domain.toLowerCase().trim();
  if (!d) return false;

  // Asset filenames disguised as hostnames
  if (/\.(js|mjs|css|png|jpe?g|gif|svg|webp|ico|woff2?|ttf|otf|map|json|xml|html?)$/.test(d)) {
    return false;
  }

  // localhost / IPs are valid
  if (d === 'localhost' || /^\d{1,3}(\.\d{1,3}){3}$/.test(d)) return true;

  // Must have at least one dot, valid TLD (>=2 chars, not all digits), and no spaces
  if (!d.includes('.') || /\s/.test(d)) return false;
  const parts = d.split('.');
  const tld = parts[parts.length - 1];
  if (!tld || tld.length < 2 || /^\d+$/.test(tld)) return false;

  // Hostname label rules (RFC 1035-ish)
  const labelRe = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
  return parts.every((p) => labelRe.test(p));
}
