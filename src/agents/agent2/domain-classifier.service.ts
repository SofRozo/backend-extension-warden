import { Injectable } from '@nestjs/common';
import type { DomainCategory, CategorizedDomain } from '../interfaces/agents.interfaces.js';

/**
 * First-layer deterministic domain classifier.
 * Handles the obvious cases — CDN infrastructure, known social platforms,
 * identity providers, email/productivity suites — so the LLM in Agent 2
 * only needs to reason about truly unknown domains.
 *
 * Rules are intentionally conservative: when in doubt, return null and
 * let the LLM decide.
 */

// ─── Known domain lists ───────────────────────────────────────────────────────

const TECH_INFRASTRUCTURE = new Set([
  // Web fonts & assets
  'fonts.googleapis.com', 'fonts.gstatic.com',
  // Package CDNs
  'unpkg.com', 'jsdelivr.net', 'cdnjs.cloudflare.com',
  // Google APIs (infrastructure only — accounts.google.com goes to IDENTITY)
  'ajax.googleapis.com', 'www.googleapis.com', 'storage.googleapis.com',
  // Analytics
  'google-analytics.com', 'googletagmanager.com', 'analytics.google.com',
  'doubleclick.net', 'googlesyndication.com', 'sentry.io', 'bugsnag.com',
  'rollbar.com', 'segment.io', 'mixpanel.com', 'amplitude.com',
  // Hosting / CDN
  'cloudflare.com', 'fastly.net', 'akamaihd.net', 'cloudfront.net',
  // Build / package tooling
  'registry.npmjs.org', 'yarnpkg.com',
  // Design / UI
  'bootstrapcdn.com', 'jquery.com',
]);

const SOCIAL_MEDIA: Record<string, string> = {
  'instagram.com': 'Instagram', 'www.instagram.com': 'Instagram',
  'facebook.com': 'Facebook', 'www.facebook.com': 'Facebook', 'fb.com': 'Facebook',
  'tiktok.com': 'TikTok', 'www.tiktok.com': 'TikTok',
  'twitter.com': 'Twitter/X', 'x.com': 'Twitter/X',
  'linkedin.com': 'LinkedIn', 'www.linkedin.com': 'LinkedIn',
  'reddit.com': 'Reddit', 'www.reddit.com': 'Reddit', 'old.reddit.com': 'Reddit',
  'youtube.com': 'YouTube', 'www.youtube.com': 'YouTube',
  'snapchat.com': 'Snapchat', 'www.snapchat.com': 'Snapchat',
  'pinterest.com': 'Pinterest',
  'twitch.tv': 'Twitch', 'www.twitch.tv': 'Twitch',
  'discord.com': 'Discord',
  'telegram.org': 'Telegram', 't.me': 'Telegram',
  'whatsapp.com': 'WhatsApp', 'web.whatsapp.com': 'WhatsApp',
};

const IDENTITY_PROVIDERS: Record<string, string> = {
  'accounts.google.com': 'Google Auth',
  'oauth2.googleapis.com': 'Google OAuth',
  'login.microsoftonline.com': 'Microsoft Auth',
  'login.live.com': 'Microsoft Live Auth',
  'appleid.apple.com': 'Apple Auth',
  'github.com': 'GitHub',
  'api.github.com': 'GitHub API',
  'auth0.com': 'Auth0',
  'okta.com': 'Okta',
  'onelogin.com': 'OneLogin',
  'login.yahoo.com': 'Yahoo Auth',
  'accounts.spotify.com': 'Spotify Auth',
};

const EMAIL_PRODUCTIVITY: Record<string, string> = {
  'mail.google.com': 'Gmail',
  'gmail.com': 'Gmail',
  'outlook.com': 'Outlook',
  'outlook.live.com': 'Outlook',
  'hotmail.com': 'Hotmail',
  'office.com': 'Microsoft Office',
  'microsoft.com': 'Microsoft',
  'drive.google.com': 'Google Drive',
  'docs.google.com': 'Google Docs',
  'sheets.google.com': 'Google Sheets',
  'slides.google.com': 'Google Slides',
  'calendar.google.com': 'Google Calendar',
  'slack.com': 'Slack',
  'notion.so': 'Notion',
  'dropbox.com': 'Dropbox',
  'box.com': 'Box',
  'trello.com': 'Trello',
  'atlassian.com': 'Atlassian',
  'jira.com': 'Jira',
  'confluence.com': 'Confluence',
};

// ─── Public result type ───────────────────────────────────────────────────────

export interface DeterministicResult {
  /** null means "unknown — needs LLM reasoning" */
  category: DomainCategory | null;
  platform?: string;
}

// ─── Service ──────────────────────────────────────────────────────────────────

@Injectable()
export class DomainClassifierService {
  /**
   * Classify a single domain using deterministic rules only.
   * Returns null category for domains that must go to the LLM.
   */
  classify(
    domain: string,
    extensionName: string,
    extensionAuthor?: string,
  ): DeterministicResult {
    const d = domain.toLowerCase();
    const dNoWww = d.replace(/^www\./, '');

    // 1. Technical infrastructure
    if (TECH_INFRASTRUCTURE.has(d) || TECH_INFRASTRUCTURE.has(dNoWww)) {
      return { category: 'infraestructura_tecnica' };
    }

    // 2. Extension's own domain (name/author match)
    if (this.isLikelyOwnDomain(dNoWww, extensionName, extensionAuthor)) {
      return { category: 'propio_extension' };
    }

    // 3. Social media
    const social = SOCIAL_MEDIA[d] ?? SOCIAL_MEDIA[dNoWww];
    if (social) return { category: 'sensible_redes_sociales', platform: social };

    // 4. Identity providers
    const identity = IDENTITY_PROVIDERS[d] ?? IDENTITY_PROVIDERS[dNoWww];
    if (identity) return { category: 'sensible_identidad', platform: identity };

    // 5. Email & productivity
    const email = EMAIL_PRODUCTIVITY[d] ?? EMAIL_PRODUCTIVITY[dNoWww];
    if (email) return { category: 'sensible_correo_productividad', platform: email };

    // Unknown — LLM must decide
    return { category: null };
  }

  /**
   * Returns the Playwright visit priority for a sensitive category.
   * Lower number = visited first.  Returns undefined for non-sensitive categories.
   */
  playwrightPriority(category: DomainCategory): number | undefined {
    const map: Partial<Record<DomainCategory, number>> = {
      sensible_financiero: 1,
      sensible_identidad: 2,
      sensible_correo_productividad: 3,
      sensible_redes_sociales: 4,
      sensible_gubernamental: 4,
      desconocido: 5,
    };
    return map[category];
  }

  buildCategorizedDomain(
    domain: string,
    category: DomainCategory,
    reasoning: string,
    playwrightPriority?: number,
  ): CategorizedDomain {
    const goesToPlaywright = playwrightPriority !== undefined;
    return { domain, category, reasoning, goesToPlaywright, playwrightPriority };
  }

  // ─── Helpers ───────────────────────────────────────────────────────────────

  private isLikelyOwnDomain(
    domain: string,
    extensionName: string,
    extensionAuthor?: string,
  ): boolean {
    const normalize = (s: string) => s.toLowerCase().replace(/[^a-z0-9]/g, '');
    const domainBase = normalize(domain.split('.')[0]);

    if (domainBase.length < 4) return false; // Too short to match reliably

    const nameParts = extensionName
      .toLowerCase()
      .split(/\s+/)
      .map(normalize)
      .filter((p) => p.length > 3);

    if (nameParts.some((p) => domainBase.includes(p) || p.includes(domainBase))) {
      return true;
    }

    if (extensionAuthor) {
      const authorBase = normalize(extensionAuthor.split(/\s+/)[0]);
      if (
        authorBase.length > 3 &&
        (domainBase.includes(authorBase) || authorBase.includes(domainBase))
      ) {
        return true;
      }
    }

    return false;
  }
}
