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
  DYNAMIC_ANALYSIS = 'dynamic_analysis',
  THREAT_INTEL = 'threat_intel',
  GENERATING_REPORT = 'generating_report',
  COMPLETED = 'completed',
  FAILED = 'failed',
}

export enum PlatformLevel {
  LEVEL_1_PUBLIC = 1,
  LEVEL_2_HONEYPOT = 2,
  LEVEL_3_RESTRICTED = 3,
}

export enum DetonationStrategy {
  STATE_INJECTION = 'state_injection',
  PASSIVE_TRIGGER = 'passive_trigger',
  DOM_FALSIFICATION = 'dom_falsification',
  DIRECT_NAVIGATION = 'direct_navigation',
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
