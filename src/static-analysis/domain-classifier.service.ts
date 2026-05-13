import { Injectable } from '@nestjs/common';
import type { DomainCategory } from '../common/interfaces/analysis.interfaces.js';

/**
 * Deterministic domain classifier. Runs during static analysis and categorises
 * every domain reference (from code or from manifest host_permissions) into
 * one of the buckets defined by `DomainCategory`. No LLM involved — the lists
 * below are curated and the matching is exact (with `www.` stripping and TLD
 * fallback for governmental domains).
 *
 * Categories `sensible_*` are flagged for prioritised visit during the dynamic
 * (Stagehand) phase. Categories `propio_extension` and `infraestructura_tecnica`
 * are dropped from the final report — they are not interesting to surface.
 * Returns `null` only when the domain matches nothing, in which case the
 * static-analysis layer files it under `resultado2_unknown`.
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
  'run.app', // Google Cloud Run
  'a.run.app',
  'appspot.com', // Google App Engine
  'herokuapp.com',
  'netlify.app',
  'vercel.app',
  'pages.dev',
  'github.io',
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
  'discord.gg': 'Discord',
  'discordapp.com': 'Discord',
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

const DATA_BROKERS: Record<string, string> = {
  // Marketing / identity resolution data brokers
  'acxiom.com': 'Acxiom',
  'liveramp.com': 'LiveRamp',
  'oracle.com/cx/marketing/data-cloud': 'Oracle Data Cloud',
  'bluekai.com': 'Oracle BlueKai',
  'datalogix.com': 'Oracle Datalogix',
  'experian.com': 'Experian',
  'experiandirect.com': 'Experian Direct',
  'equifax.com': 'Equifax',
  'transunion.com': 'TransUnion',
  'lexisnexis.com': 'LexisNexis',
  'risk.lexisnexis.com': 'LexisNexis Risk',
  'epsilon.com': 'Epsilon',
  'merkleinc.com': 'Merkle',
  'towerdata.com': 'TowerData',
  'spokeo.com': 'Spokeo',
  'whitepages.com': 'Whitepages',
  'beenverified.com': 'BeenVerified',
  'intelius.com': 'Intelius',
  'mylife.com': 'MyLife',
  'peoplefinder.com': 'PeopleFinder',
  'pipl.com': 'Pipl',
  'thomsonreuters.com': 'Thomson Reuters',
  // Ad-tech tracking / DMPs that exfiltrate behavioural data
  'criteo.com': 'Criteo',
  'taboola.com': 'Taboola',
  'outbrain.com': 'Outbrain',
  'pubmatic.com': 'PubMatic',
  'rubiconproject.com': 'Rubicon Project',
  'openx.net': 'OpenX',
  'adsrvr.org': 'The Trade Desk',
  'adnxs.com': 'Xandr/AppNexus',
  'rlcdn.com': 'LiveRamp ATS',
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
  /** null means "unknown — not in any curated list" */
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

    if (
      TECH_INFRASTRUCTURE.has(d) ||
      TECH_INFRASTRUCTURE.has(dNoWww) ||
      d.endsWith('.run.app') ||
      d.endsWith('.appspot.com') ||
      d.endsWith('.netlify.app') ||
      d.endsWith('.vercel.app')
    ) {
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

    const broker = DATA_BROKERS[d] ?? DATA_BROKERS[dNoWww];
    if (broker) return { category: 'sensible_data_broker', platform: broker };

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
      sensible_data_broker: 3,
      sensible_llm: 4,
      sensible_correo_productividad: 5,
      sensible_redes_sociales: 6,
      sensible_gubernamental: 6,
      desconocido: 7,
    };
    return map[category];
  }

  /** True for sensitive categories that should be in resultado2_priority */
  isPriority(category: DomainCategory): boolean {
    const priority: DomainCategory[] = [
      'sensible_financiero',
      'sensible_identidad',
      'sensible_data_broker',
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
    const parts = domain.split('.');

    // For api.gethappydog.com -> we want "gethappydog"
    let domainBase = '';
    if (parts.length >= 2) {
      // Very naive "registrable domain" logic: take the part before the TLD
      domainBase = normalize(parts[parts.length - 2]);
    } else {
      domainBase = normalize(parts[0]);
    }

    if (domainBase.length < 3) return false;

    const nameNormalized = normalize(extensionName);
    const nameParts = extensionName
      .toLowerCase()
      .split(/\s+/)
      .map(normalize)
      .filter((p) => p.length > 3);

    // 1. Exact match with normalized name (happydog vs happy dog)
    if (
      nameNormalized.includes(domainBase) ||
      domainBase.includes(nameNormalized)
    ) {
      return true;
    }

    // 2. Partial match with name parts
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
