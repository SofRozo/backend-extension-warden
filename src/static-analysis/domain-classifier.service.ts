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
  'cloudfunctions.net', // Google Cloud Functions / Firebase Functions
  'appspot.com', // Google App Engine
  'firebaseapp.com',
  'firebaseio.com',
  'web.app',
  'herokuapp.com',
  'netlify.app',
  'vercel.app',
  'pages.dev',
  'github.io',
  'github.com',
  'api.github.com',
  'raw.githubusercontent.com',
  'objects.githubusercontent.com',
  'vuejs.org',
  'v3-migration.vuejs.org',
  'cli.vuejs.org',
  'reactjs.org',
  'svelte.dev',
  'angular.io',
  'w3.org',
  'www.w3.org',
  'meyerweb.com',
  'schema.org',
  'tc39.es',
  'ecma-international.org',
  'developer.mozilla.org',
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

// ─── Entity resolution — groups regional variants under one brand ─────────────
//
// Used to de-duplicate: amazon.co.uk, amazon.de, amazon.co.jp, etc. all belong
// to the same "Amazon" entity. Regex patterns are tested against the
// `dNoWww` form of the domain.

export interface EntityClassification {
  entity: string;
  category: DomainCategory;
  /** Human-readable description of why the entity is notable. */
  description: string;
}

const ENTITY_PATTERNS: Array<{
  regex: RegExp;
  entity: string;
  category: DomainCategory;
  description: string;
}> = [
  {
    regex: /^amazon\.(com|co\.uk|co\.jp|de|fr|es|it|in|ca|com\.mx|com\.br|com\.au|sg|ae|nl|se|pl|com\.tr|eg|sa)$/i,
    entity: 'Amazon',
    category: 'infraestructura_tecnica',
    description: 'Amazon e-commerce platform (regional variant)',
  },
  {
    regex: /^(smile\.amazon|sellercentral\.amazon|images-amazon|media-amazon|ssl-images-amazon|completion\.amazon|ecx\.images-amazon|assoc-amazon)\.(com|co\.uk|co\.jp|de|fr|es|it|in|ca)$/i,
    entity: 'Amazon',
    category: 'infraestructura_tecnica',
    description: 'Amazon infrastructure subdomain',
  },
  {
    regex: /^(aax|aax-eu|aax-fe)\.amazon-adsystem\.com$/i,
    entity: 'Amazon Ads',
    category: 'sensible_data_broker',
    description: 'Amazon advertising / tracking system',
  },
  {
    regex: /^(www\.)?google\.(com|co\.uk|co\.jp|de|fr|es|it|ca|com\.au|com\.br|com\.mx|co\.in|com\.ar)$/i,
    entity: 'Google',
    category: 'infraestructura_tecnica',
    description: 'Google search engine (regional variant)',
  },
  {
    regex: /^(www\.)?facebook\.(com|co\.uk|de|fr|es)$|^(www\.)?instagram\.com$|^fbcdn\.net$|^cdninstagram\.com$/i,
    entity: 'Meta',
    category: 'sensible_redes_sociales',
    description: 'Meta platform (Facebook / Instagram)',
  },
  {
    regex: /^10xprofit\.io$|^app\.10xprofit\.io$/i,
    entity: '10xProfit',
    category: 'sensible_data_broker',
    description: 'Lead generation / commerce data third-party',
  },
  {
    regex: /^ecomstal\.(com|io|net)$/i,
    entity: 'EcomStal',
    category: 'sensible_data_broker',
    description: 'E-commerce analytics / lead generation third-party',
  },
];

// ─── Public result type ───────────────────────────────────────────────────────

export interface DeterministicResult {
  /** null means "unknown — not in any curated list" */
  category: DomainCategory | null;
  platform?: string;
  /** Set when domain matched an entity regex (multi-regional brand). */
  entity?: string;
}

const RESIDENTIAL_PROXY_NETWORKS = new Set([
  'geosurf.io',
  'luminati.io',
  'brightdata.com',
  'oxylabs.io',
  'smartproxy.com',
  'iproyal.com',
  'packetstream.io',
  'peer2profit.com',
]);

// ─── Service ──────────────────────────────────────────────────────────────────

@Injectable()
export class DomainClassifierService {
  /**
   * Extracts the registrable domain (eTLD+1) from a hostname.
   * This is the generalizable grouping key for unknown domains:
   *   api.evil.io  → evil.io
   *   cdn.evil.io  → evil.io
   *   sub.co.uk    → sub.co.uk   (single-label SLD, returned as-is)
   *
   * Handles common two-label eTLDs (co.uk, com.br, org.au, etc.) without
   * requiring an external public-suffix-list library.
   */
  registrableDomain(domain: string): string {
    const d = domain.toLowerCase().replace(/^www\./, '');
    const parts = d.split('.');
    if (parts.length <= 2) return d;

    // Common two-label eTLDs: co.uk, com.au, com.br, co.jp, org.uk, net.au…
    const TWO_LABEL_ETLD = /^(co|com|org|net|gov|edu|ac|sch|me|ne|or)\.[a-z]{2}$/;
    const lastTwo = parts.slice(-2).join('.');
    if (TWO_LABEL_ETLD.test(lastTwo)) {
      // e.g. api.amazon.co.uk → parts = [api, amazon, co, uk] → take last 3
      return parts.slice(-3).join('.');
    }
    // Standard: take last two parts  (api.evil.io → evil.io)
    return parts.slice(-2).join('.');
  }

  /**
   * Resolves any domain to a grouping entity. Always returns a value — never null.
   *
   * Priority:
   *  1. Curated ENTITY_PATTERNS — for complex multi-regional brands (Amazon,
   *     Meta, Google) whose subdomains would otherwise produce many separate entries.
   *  2. Dynamic fallback — extracts the registrable domain (eTLD+1) so the LLM
   *     receives "mixpanel.com" instead of "api.mixpanel.com", and groups all
   *     subdomains of an unknown third-party automatically.
   *
   * Examples:
   *   amazon.co.uk          → { entity: "Amazon",        category: "infraestructura_tecnica" }
   *   api.mixpanel.com      → { entity: "mixpanel.com",  category: "desconocido" }
   *   mixpanel.com          → { entity: "mixpanel.com",  category: "desconocido" }
   *   data.happydog-app.net → { entity: "happydog-app.net", category: "desconocido" }
   *   super-ads-2026.net    → { entity: "super-ads-2026.net", category: "desconocido" }
   */
  resolveEntity(domain: string): EntityClassification {
    const dNoWww = domain.toLowerCase().replace(/^www\./, '');

    // 1. Curated patterns (Amazon, Meta, 10xProfit, etc.)
    for (const p of ENTITY_PATTERNS) {
      if (p.regex.test(dNoWww)) {
        return { entity: p.entity, category: p.category, description: p.description };
      }
    }

    // 2. Dynamic fallback — always extract the registrable domain (eTLD+1).
    //    The LLM uses its world-knowledge to reason about what the entity is.
    const rootDomain = this.registrableDomain(dNoWww);
    return {
      entity: rootDomain,
      category: 'desconocido',
      description: 'Uncategorized third-party domain',
    };
  }

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
      d.endsWith('.cloudfunctions.net') ||
      d.endsWith('.appspot.com') ||
      d.endsWith('.firebaseapp.com') ||
      d.endsWith('.firebaseio.com') ||
      d.endsWith('.web.app') ||
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

    const hostOnly = dNoWww.split('.').slice(-2).join('.');
    if (
      RESIDENTIAL_PROXY_NETWORKS.has(dNoWww) ||
      RESIDENTIAL_PROXY_NETWORKS.has(hostOnly)
    ) {
      return { category: 'sensible_data_broker' };
    }

    // Entity regex fallback — catches regional variants and known third-parties
    // not in the exact-match sets above.
    const entityMatch = this.resolveEntity(domain);
    if (entityMatch) {
      return {
        category: entityMatch.category,
        platform: entityMatch.entity,
        entity: entityMatch.entity,
      };
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
