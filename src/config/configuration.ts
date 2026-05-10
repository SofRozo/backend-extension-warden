import * as os from 'os';
import * as path from 'path';

/**
 * Default base dir for ephemeral analysis artifacts (CRX downloads, extracted files).
 * On Linux/Docker keeps /tmp/ext-sandbox so existing volumes/tmpfs mounts work.
 * On Windows native falls back to OS temp folder so paths actually exist.
 */
function defaultEphemeralBase(): string {
  if (process.platform === 'win32') {
    return path.join(os.tmpdir(), 'ext-sandbox');
  }
  return '/tmp/ext-sandbox';
}

export default () => ({
  port: parseInt(process.env.PORT || '3000', 10),
  database: {
    host: process.env.DB_HOST || 'localhost',
    port: parseInt(process.env.DB_PORT || '5432', 10),
    username: process.env.DB_USERNAME || 'extsandbox',
    password: process.env.DB_PASSWORD || 'extsandbox_secret',
    name: process.env.DB_NAME || 'extsandbox',
  },
  redis: {
    host: process.env.REDIS_HOST || 'localhost',
    port: parseInt(process.env.REDIS_PORT || '6379', 10),
    password: process.env.REDIS_PASSWORD || '',
  },
  analysis: {
    preprocessTimeoutMs: parseInt(process.env.PREPROCESS_TIMEOUT_MS || '180000', 10),
    staticTimeoutMs: parseInt(process.env.STATIC_TIMEOUT_MS || '60000', 10),
    dynamicTimeoutMs: parseInt(process.env.DYNAMIC_TIMEOUT_MS || '180000', 10),
    maxConcurrentWorkers: parseInt(
      process.env.MAX_CONCURRENT_WORKERS || '10',
      10,
    ),
    crxDownloadDir:
      process.env.CRX_DOWNLOAD_DIR || path.join(defaultEphemeralBase(), 'crx'),
    extractDir:
      process.env.EXTRACT_DIR || path.join(defaultEphemeralBase(), 'extracted'),
    useStagehand: process.env.ANALYSIS_USE_STAGEHAND === 'true',
  },
  threatIntel: {
    virusTotalApiKey: process.env.VIRUSTOTAL_API_KEY || '',
    urlScanApiKey: process.env.URLSCAN_API_KEY || '',
    abuseIpdbApiKey: process.env.ABUSEIPDB_API_KEY || '',
    timeoutMs: parseInt(process.env.THREAT_INTEL_TIMEOUT_MS || '10000', 10),
    cacheTtlSeconds: parseInt(
      process.env.THREAT_INTEL_CACHE_TTL || '86400',
      10,
    ),
  },
  honeypot: {
    storageStatePath: process.env.STORAGE_STATE_PATH || '/data/honeypot/states',
    encryptionKey: process.env.HONEYPOT_ENCRYPTION_KEY || '',
  },
  demo: {
    enabled: process.env.DEMO_MODE === 'true',
    slowMo: parseInt(process.env.DEMO_SLOW_MO || '800', 10),
    storageStatePath: process.env.DEMO_STORAGE_STATE_PATH || './demo-states',
  },
});
