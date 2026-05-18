export enum RiskLevel {
  CRITICAL = 'critical',
  HIGH = 'high',
  MEDIUM = 'medium',
  LOW = 'low',
  INFORMATIONAL = 'informational',
  NONE = 'none',
}

export enum AnalysisStatus {
  QUEUED = 'queued',
  DOWNLOADING = 'downloading',
  PREPROCESSING = 'preprocessing',
  AI_ANALYSIS = 'ai_analysis',
  STATIC_ANALYSIS = 'static_analysis',
  THREAT_INTEL = 'threat_intel',
  GENERATING_REPORT = 'generating_report',
  COMPLETED = 'completed',
  FAILED = 'failed',
}

export enum FindingCategory {
  DATA_THEFT = 'data_theft',
  KEYLOGGER = 'keylogger',
  INJECTION = 'injection',
  EXFILTRATION = 'exfiltration',
  DOMAIN_TARGETING = 'domain_targeting',
  PERSISTENCE = 'persistence',
  INTERCEPTION = 'interception',
  EVASION = 'evasion',
  CLIPBOARD = 'clipboard',
  FINGERPRINTING = 'fingerprinting',
  PRIVACY_RISK = 'privacy_risk',
  DROPPER = 'dropper',
}
