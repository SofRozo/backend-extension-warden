import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import axios from 'axios';
import { StructuredLogger } from '../common/logger/logger.service.js';
import { ThreatIntelResult } from '../common/interfaces/analysis.interfaces.js';

@Injectable()
export class ThreatIntelService {
  private cache = new Map<string, { result: ThreatIntelResult[]; expiresAt: number }>();

  // Hard cap: never query more than this many domains per job (any provider)
  private static readonly GLOBAL_MAX_DOMAINS = 30;
  // VirusTotal free tier: 4 req/min → 1 every 16s to stay safely under limit
  private static readonly VT_DELAY_MS = 16_000;
  private static readonly VT_MAX_DOMAINS = 8;
  // URLScan free tier: ~40 req/min → 1 every 1.5s
  private static readonly URLSCAN_DELAY_MS = 1_500;
  private static readonly URLSCAN_MAX_DOMAINS = 20;

  constructor(
    private readonly config: ConfigService,
    private readonly logger: StructuredLogger,
  ) { }

  async queryDomain(
    domain: string,
    jobId: string,
  ): Promise<ThreatIntelResult[]> {
    const cached = this.cache.get(domain);
    if (cached && cached.expiresAt > Date.now()) {
      this.logger.logWithJob(jobId, 'info', `Cache hit for ${domain}`, 'ThreatIntelService');
      return cached.result;
    }

    const timeoutMs = this.config.get<number>('threatIntel.timeoutMs') || 10000;

    const settled = await Promise.allSettled([
      this.queryVirusTotal(domain, timeoutMs, jobId),
    ]);

    const results: ThreatIntelResult[] = [];
    for (const r of settled) {
      if (r.status === 'fulfilled' && r.value) results.push(r.value);
    }

    const ttl = (this.config.get<number>('threatIntel.cacheTtlSeconds') || 86400) * 1000;
    this.cache.set(domain, { result: results, expiresAt: Date.now() + ttl });

    return results;
  }

  async queryDomains(
    domains: string[],
    jobId: string,
  ): Promise<ThreatIntelResult[]> {
    const uniqueDomains = [...new Set(domains)];
    const allResults: ThreatIntelResult[] = [];
    const uncached: string[] = [];

    // Serve cached results immediately
    for (const domain of uniqueDomains) {
      const cached = this.cache.get(domain);
      if (cached && cached.expiresAt > Date.now()) {
        this.logger.logWithJob(jobId, 'info', `Cache hit for ${domain}`, 'ThreatIntelService');
        allResults.push(...cached.result);
      } else {
        uncached.push(domain);
      }
    }

    if (uncached.length === 0) return allResults;

    // Apply global cap — extensions like coupon/shopping tools can have 1000s of domains
    const capped = uncached.slice(0, ThreatIntelService.GLOBAL_MAX_DOMAINS);
    if (uncached.length > ThreatIntelService.GLOBAL_MAX_DOMAINS) {
      this.logger.logWithJob(
        jobId,
        'warn',
        `ThreatIntel: capping ${uncached.length} domains to ${ThreatIntelService.GLOBAL_MAX_DOMAINS} to respect API rate limits`,
        'ThreatIntelService',
      );
    }

    const timeoutMs = this.config.get<number>('threatIntel.timeoutMs') || 10_000;
    const ttl = (this.config.get<number>('threatIntel.cacheTtlSeconds') || 86400) * 1000;
    const domainResults = new Map<string, ThreatIntelResult[]>();
    for (const d of capped) domainResults.set(d, []);

    // Only using VirusTotal as requested

    // VirusTotal: sequential with delay to respect 4 req/min free tier
    const vtDomains = capped.slice(0, ThreatIntelService.VT_MAX_DOMAINS);
    if (vtDomains.length > 0) {
      const estMinutes = Math.ceil((vtDomains.length * ThreatIntelService.VT_DELAY_MS) / 60_000);
      this.logger.logWithJob(jobId, 'info',
        `VirusTotal: querying ${vtDomains.length} domains sequentially (~${estMinutes}min, rate-limited)`,
        'ThreatIntelService');
    }
    for (let i = 0; i < vtDomains.length; i++) {
      const domain = vtDomains[i];
      const vtResult = await this.queryVirusTotal(domain, timeoutMs, jobId);
      if (vtResult) domainResults.get(domain)!.push(vtResult);
      if (i < vtDomains.length - 1) {
        await new Promise((r) => setTimeout(r, ThreatIntelService.VT_DELAY_MS));
      }
    }

    // Cache and collect
    for (const [domain, results] of domainResults) {
      this.cache.set(domain, { result: results, expiresAt: Date.now() + ttl });
      allResults.push(...results);
    }

    return allResults;
  }

  private async queryVirusTotal(
    domain: string,
    timeoutMs: number,
    jobId: string,
  ): Promise<ThreatIntelResult | null> {
    const apiKey = this.config.get<string>('threatIntel.virusTotalApiKey');
    if (!apiKey) {
      this.logger.logWithJob(
        jobId,
        'warn',
        'VirusTotal API key not configured',
        'ThreatIntelService',
      );
      return null;
    }

    try {
      const response = await axios.get(
        `https://www.virustotal.com/api/v3/domains/${domain}`,
        {
          headers: { 'x-apikey': apiKey },
          timeout: timeoutMs,
        },
      );

      const data = response.data?.data?.attributes;
      const lastAnalysisStats = data?.last_analysis_stats || {};
      const malicious = lastAnalysisStats.malicious || 0;
      const suspicious = lastAnalysisStats.suspicious || 0;
      const total =
        malicious +
        suspicious +
        (lastAnalysisStats.harmless || 0) +
        (lastAnalysisStats.undetected || 0);

      return {
        domain,
        provider: 'virustotal',
        isMalicious: malicious > 0 || suspicious > 2,
        score: total > 0 ? (malicious + suspicious) / total : 0,
        categories: data?.categories
          ? Object.values(data.categories) as string[]
          : [],
        details: {
          malicious,
          suspicious,
          harmless: lastAnalysisStats.harmless || 0,
          undetected: lastAnalysisStats.undetected || 0,
          reputation: data?.reputation,
        },
        queriedAt: new Date(),
      };
    } catch (err) {
      this.logger.logWithJob(
        jobId,
        'warn',
        `VirusTotal query failed for ${domain}: ${err instanceof Error ? err.message : String(err)}`,
        'ThreatIntelService',
      );
      return null;
    }
  }

  private async queryUrlScan(
    domain: string,
    timeoutMs: number,
    jobId: string,
  ): Promise<ThreatIntelResult | null> {
    const apiKey = this.config.get<string>('threatIntel.urlScanApiKey');

    try {
      const headers: Record<string, string> = {};
      if (apiKey) headers['API-Key'] = apiKey;

      const response = await axios.get(
        `https://urlscan.io/api/v1/search/?q=domain:${domain}`,
        { headers, timeout: timeoutMs },
      );

      const results = response.data?.results || [];
      const maliciousCount = results.filter(
        (r: any) => r.verdicts?.overall?.malicious,
      ).length;

      return {
        domain,
        provider: 'urlscan',
        isMalicious: maliciousCount > 0,
        score:
          results.length > 0 ? maliciousCount / results.length : 0,
        categories: results
          .filter((r: any) => r.verdicts?.overall?.tags)
          .flatMap((r: any) => r.verdicts.overall.tags)
          .slice(0, 10) as string[],
        details: {
          totalScans: results.length,
          maliciousScans: maliciousCount,
        },
        queriedAt: new Date(),
      };
    } catch (err) {
      this.logger.logWithJob(
        jobId,
        'warn',
        `URLScan query failed for ${domain}: ${err instanceof Error ? err.message : String(err)}`,
        'ThreatIntelService',
      );
      return null;
    }
  }

  private async queryAbuseIPDB(
    domain: string,
    timeoutMs: number,
    jobId: string,
  ): Promise<ThreatIntelResult | null> {
    const apiKey = this.config.get<string>('threatIntel.abuseIpdbApiKey');
    if (!apiKey) {
      return null;
    }

    try {
      // AbuseIPDB works with IPs, so we first resolve the domain
      const dns = await import('dns');
      const { promisify } = await import('util');
      const resolve4 = promisify(dns.resolve4);

      let ips: string[];
      try {
        ips = await resolve4(domain);
      } catch {
        return null;
      }

      if (ips.length === 0) return null;

      const response = await axios.get(
        `https://api.abuseipdb.com/api/v2/check`,
        {
          params: { ipAddress: ips[0], maxAgeInDays: 90 },
          headers: {
            Key: apiKey,
            Accept: 'application/json',
          },
          timeout: timeoutMs,
        },
      );

      const data = response.data?.data;
      const score = (data?.abuseConfidenceScore || 0) / 100;

      return {
        domain,
        provider: 'abuseipdb',
        isMalicious: score > 0.5,
        score,
        categories: data?.usageType ? [data.usageType] : [],
        details: {
          ip: ips[0],
          abuseConfidenceScore: data?.abuseConfidenceScore,
          totalReports: data?.totalReports,
          countryCode: data?.countryCode,
          isp: data?.isp,
        },
        queriedAt: new Date(),
      };
    } catch (err) {
      this.logger.logWithJob(
        jobId,
        'warn',
        `AbuseIPDB query failed for ${domain}: ${err instanceof Error ? err.message : String(err)}`,
        'ThreatIntelService',
      );
      return null;
    }
  }
}
