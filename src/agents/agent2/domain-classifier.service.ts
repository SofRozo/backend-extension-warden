import { Injectable } from '@nestjs/common';
import type { DomainCategory } from '../interfaces/agents.interfaces.js';

/**
 * Deterministic domain classifier — runs in the preprocessor before any LLM
 * is involved. Returns null when the domain is unknown so the LLM (Agent 3)
 * can reason about it.
 */

// ─── Known domain lists ───────────────────────────────────────────────────────

const TECH_INFRASTRUCTURE = new Set([
  'fonts.googleapis.com',
  'fonts.gstatic.com',
  'unpkg.com',
  'jsdelivr.net',
  'cdnjs.cloudflare.com',
  'ajax.googleapis.com',
  'www.googleapis.com',
  'storage.googleapis.com',
  'google-analytics.com',
  'googletagmanager.com',
  'analytics.google.com',
  'doubleclick.net',
  'googlesyndication.com',
  'sentry.io',
  'bugsnag.com',
  'rollbar.com',
  'segment.io',
  'mixpanel.com',
  'amplitude.com',
  'cloudflare.com',
  'fastly.net',
  'akamaihd.net',
  'cloudfront.net',
  'registry.npmjs.org',
  'yarnpkg.com',
  'bootstrapcdn.com',
  'jquery.com',
]);

const SOCIAL_MEDIA: Record<string, string> = {
  'instagram.com': 'Instagram',
  'www.instagram.com': 'Instagram',
  'facebook.com': 'Facebook',
  'www.facebook.com': 'Facebook',
  'fb.com': 'Facebook',
  'tiktok.com': 'TikTok',
  'www.tiktok.com': 'TikTok',
  'twitter.com': 'Twitter/X',
  'x.com': 'Twitter/X',
  'linkedin.com': 'LinkedIn',
  'www.linkedin.com': 'LinkedIn',
  'reddit.com': 'Reddit',
  'www.reddit.com': 'Reddit',
  'old.reddit.com': 'Reddit',
  'youtube.com': 'YouTube',
  'www.youtube.com': 'YouTube',
  'snapchat.com': 'Snapchat',
  'www.snapchat.com': 'Snapchat',
  'pinterest.com': 'Pinterest',
  'twitch.tv': 'Twitch',
  'www.twitch.tv': 'Twitch',
  'discord.com': 'Discord',
  'telegram.org': 'Telegram',
  't.me': 'Telegram',
  'whatsapp.com': 'WhatsApp',
  'web.whatsapp.com': 'WhatsApp',
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

const FINANCIAL: Record<string, string> = {
  'paypal.com': 'PayPal',
  'stripe.com': 'Stripe',
  'mercadopago.com': 'Mercado Pago',
  'mercadopago.com.co': 'Mercado Pago',
  'bancolombia.com': 'Bancolombia',
  'davivienda.com': 'Davivienda',
  'davivienda.com.co': 'Davivienda',
  'bbva.com': 'BBVA',
  'nequi.com.co': 'Nequi',
  'chase.com': 'Chase',
  'bankofamerica.com': 'Bank of America',
  'wellsfargo.com': 'Wells Fargo',
  'citibank.com': 'Citibank',
  'nubank.com.br': 'Nubank',
  'nu.com.co': 'Nu',
  'binance.com': 'Binance',
  'coinbase.com': 'Coinbase',
  'kraken.com': 'Kraken',
};

const GOVERNMENT: Record<string, string> = {
  'dian.gov.co': 'DIAN Colombia',
  'registraduria.gov.co': 'Registraduría Colombia',
  'sisben.gov.co': 'SISBEN Colombia',
  'irs.gov': 'IRS US',
  'gov.uk': 'UK Government',
};

const LLM_PLATFORMS: Record<string, string> = {
  'chat.openai.com': 'ChatGPT',
  'chatgpt.com': 'ChatGPT',
  'platform.openai.com': 'OpenAI Platform',
  'api.openai.com': 'OpenAI API',
  'claude.ai': 'Claude',
  'anthropic.com': 'Anthropic',
  'api.anthropic.com': 'Anthropic API',
  'gemini.google.com': 'Gemini',
  'bard.google.com': 'Bard',
  'aistudio.google.com': 'Google AI Studio',
  'generativelanguage.googleapis.com': 'Google Gen Language',
  'copilot.microsoft.com': 'Microsoft Copilot',
  'bing.com/chat': 'Bing Chat',
  'perplexity.ai': 'Perplexity',
  'huggingface.co': 'HuggingFace',
  'mistral.ai': 'Mistral',
  'cohere.ai': 'Cohere',
  'cohere.com': 'Cohere',
  'replicate.com': 'Replicate',
  'character.ai': 'Character.AI',
  'poe.com': 'Poe',
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
  classify(
    domain: string,
    extensionName: string,
    extensionAuthor?: string,
  ): DeterministicResult {
    const d = domain.toLowerCase();
    const dNoWww = d.replace(/^www\./, '');

    if (TECH_INFRASTRUCTURE.has(d) || TECH_INFRASTRUCTURE.has(dNoWww)) {
      return { category: 'infraestructura_tecnica' };
    }

    if (this.isLikelyOwnDomain(dNoWww, extensionName, extensionAuthor)) {
      return { category: 'propio_extension' };
    }

    const llm = LLM_PLATFORMS[d] ?? LLM_PLATFORMS[dNoWww];
    if (llm) return { category: 'sensible_llm', platform: llm };

    const financial = FINANCIAL[d] ?? FINANCIAL[dNoWww];
    if (financial)
      return { category: 'sensible_financiero', platform: financial };

    const social = SOCIAL_MEDIA[d] ?? SOCIAL_MEDIA[dNoWww];
    if (social)
      return { category: 'sensible_redes_sociales', platform: social };

    const identity = IDENTITY_PROVIDERS[d] ?? IDENTITY_PROVIDERS[dNoWww];
    if (identity) return { category: 'sensible_identidad', platform: identity };

    const email = EMAIL_PRODUCTIVITY[d] ?? EMAIL_PRODUCTIVITY[dNoWww];
    if (email)
      return { category: 'sensible_correo_productividad', platform: email };

    const gov = GOVERNMENT[d] ?? GOVERNMENT[dNoWww];
    if (gov) return { category: 'sensible_gubernamental', platform: gov };

    if (/\.gov(\.[a-z]{2})?$/i.test(dNoWww)) {
      return { category: 'sensible_gubernamental' };
    }

    return { category: null };
  }

  /**
   * Visit priority for sensitive categories. Lower = first.
   * Returns undefined for non-priority categories.
   */
  playwrightPriority(category: DomainCategory): number | undefined {
    const map: Partial<Record<DomainCategory, number>> = {
      sensible_financiero: 1,
      sensible_identidad: 2,
      sensible_llm: 3,
      sensible_correo_productividad: 4,
      sensible_redes_sociales: 5,
      sensible_gubernamental: 5,
      desconocido: 6,
    };
    return map[category];
  }

  /** True for sensitive categories that should be in resultado2_priority */
  isPriority(category: DomainCategory): boolean {
    const priority: DomainCategory[] = [
      'sensible_financiero',
      'sensible_identidad',
      'sensible_llm',
      'sensible_correo_productividad',
      'sensible_redes_sociales',
      'sensible_gubernamental',
    ];
    return priority.includes(category);
  }

  // ─── Helpers ───────────────────────────────────────────────────────────────

  private isLikelyOwnDomain(
    domain: string,
    extensionName: string,
    extensionAuthor?: string,
  ): boolean {
    const normalize = (s: string) => s.toLowerCase().replace(/[^a-z0-9]/g, '');
    const domainBase = normalize(domain.split('.')[0]);

    if (domainBase.length < 4) return false;

    const nameParts = extensionName
      .toLowerCase()
      .split(/\s+/)
      .map(normalize)
      .filter((p) => p.length > 3);

    if (
      nameParts.some((p) => domainBase.includes(p) || p.includes(domainBase))
    ) {
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
