import {
  FindingCategory,
  RiskLevel,
} from '../../common/enums/risk-level.enum.js';

export interface RiskPattern {
  category: FindingCategory;
  severity: RiskLevel;
  description: string;
  astPatterns: AstPattern[];
}

export interface AstPattern {
  type: 'call' | 'member' | 'assignment' | 'event_listener';
  object?: string;
  property?: string;
  callee?: string;
  arguments?: string[];
}

export const RISK_PATTERNS: RiskPattern[] = [
  // Data Theft
  {
    category: FindingCategory.DATA_THEFT,
    severity: RiskLevel.CRITICAL,
    description: 'Accesses password fields',
    astPatterns: [
      {
        type: 'call',
        callee: 'document.querySelector',
        arguments: ['input[type="password"]', 'input[type=password]'],
      },
      {
        type: 'call',
        callee: 'document.querySelectorAll',
        arguments: ['input[type="password"]', 'input[type=password]'],
      },
    ],
  },
  {
    category: FindingCategory.DATA_THEFT,
    severity: RiskLevel.HIGH,
    description: 'Accesses form data',
    astPatterns: [{ type: 'member', object: 'document', property: 'forms' }],
  },
  {
    category: FindingCategory.DATA_THEFT,
    severity: RiskLevel.HIGH,
    description: 'Reads page text content',
    astPatterns: [
      { type: 'member', property: 'innerText' },
      { type: 'member', property: 'textContent' },
    ],
  },
  {
    category: FindingCategory.DATA_THEFT,
    severity: RiskLevel.HIGH,
    description: 'Accesses user selection',
    astPatterns: [
      {
        type: 'call',
        callee: 'window.getSelection',
      },
    ],
  },
  {
    category: FindingCategory.DATA_THEFT,
    severity: RiskLevel.CRITICAL,
    description: 'Accesses cookies',
    astPatterns: [
      { type: 'member', object: 'document', property: 'cookie' },
      { type: 'call', callee: 'chrome.cookies.get' },
      { type: 'call', callee: 'chrome.cookies.getAll' },
    ],
  },

  // Keyloggers
  {
    category: FindingCategory.KEYLOGGER,
    severity: RiskLevel.CRITICAL,
    description: 'Registers keyboard event listeners',
    astPatterns: [
      {
        type: 'event_listener',
        arguments: ['keyup'],
      },
      {
        type: 'event_listener',
        arguments: ['keypress'],
      },
      {
        type: 'event_listener',
        arguments: ['keydown'],
      },
    ],
  },
  {
    category: FindingCategory.KEYLOGGER,
    severity: RiskLevel.HIGH,
    description: 'Intercepts form submissions',
    astPatterns: [
      {
        type: 'event_listener',
        arguments: ['submit'],
      },
    ],
  },
  {
    category: FindingCategory.KEYLOGGER,
    severity: RiskLevel.MEDIUM,
    description: 'Reacts to user input (e.g., for shortcuts or chat)',
    astPatterns: [
      {
        type: 'event_listener',
        arguments: ['input'],
      },
      {
        type: 'event_listener',
        arguments: ['change'],
      },
    ],
  },

  // Injection / Phishing
  {
    category: FindingCategory.INJECTION,
    severity: RiskLevel.CRITICAL,
    description: 'Creates script elements dynamically',
    astPatterns: [
      {
        type: 'call',
        callee: 'document.createElement',
        arguments: ['script'],
      },
    ],
  },
  {
    category: FindingCategory.INJECTION,
    severity: RiskLevel.MEDIUM,
    description:
      'Modifies page content or UI (may be used for pet/theme features)',
    astPatterns: [{ type: 'assignment', property: 'innerHTML' }],
  },
  {
    category: FindingCategory.INJECTION,
    severity: RiskLevel.HIGH,
    description: 'Uses document.write to inject content',
    astPatterns: [
      { type: 'call', callee: 'document.write' },
      { type: 'call', callee: 'document.writeln' },
    ],
  },
  {
    category: FindingCategory.INJECTION,
    severity: RiskLevel.CRITICAL,
    description: 'Creates iframes dynamically',
    astPatterns: [
      {
        type: 'call',
        callee: 'document.createElement',
        arguments: ['iframe'],
      },
    ],
  },
  {
    category: FindingCategory.INJECTION,
    severity: RiskLevel.HIGH,
    description: 'Injects and executes dynamic scripts (scripting API)',
    astPatterns: [
      { type: 'call', callee: 'chrome.scripting.executeScript' },
      { type: 'call', callee: 'chrome.tabs.executeScript' },
    ],
  },

  // Evasion / Dynamic code execution
  // NOTE: new Function() and setTimeout/setInterval(string) are already detected
  // directly in ast-parser.service.ts to avoid duplicate findings.
  {
    category: FindingCategory.EVASION,
    severity: RiskLevel.CRITICAL,
    description: 'Executes code from a string at runtime (eval)',
    astPatterns: [{ type: 'call', callee: 'eval' }],
  },
  {
    category: FindingCategory.EVASION,
    severity: RiskLevel.MEDIUM,
    description: 'Clears console output (anti-debugging signal)',
    astPatterns: [{ type: 'call', callee: 'console.clear' }],
  },
  {
    category: FindingCategory.EVASION,
    severity: RiskLevel.HIGH,
    description: 'Reads or modifies installed extensions (anti-AV / spying)',
    astPatterns: [
      { type: 'call', callee: 'chrome.management.getAll' },
      { type: 'call', callee: 'chrome.management.setEnabled' },
      { type: 'call', callee: 'chrome.management.uninstallSelf' },
    ],
  },

  // Clipboard theft
  {
    category: FindingCategory.CLIPBOARD,
    severity: RiskLevel.CRITICAL,
    description: 'Reads data from the system clipboard',
    astPatterns: [
      { type: 'call', callee: 'navigator.clipboard.readText' },
      { type: 'call', callee: 'navigator.clipboard.read' },
    ],
  },
  {
    category: FindingCategory.CLIPBOARD,
    severity: RiskLevel.HIGH,
    description: 'Reads clipboard via legacy execCommand paste',
    astPatterns: [
      { type: 'call', callee: 'document.execCommand', arguments: ['paste'] },
    ],
  },

  // Fingerprinting
  // Confidence is intentionally low (~0.5) — canvas is common in image editors,
  // games, and chart libs. Only actionable when combined with a network sink.
  {
    category: FindingCategory.FINGERPRINTING,
    severity: RiskLevel.MEDIUM,
    description: 'Canvas pixel read — potential fingerprinting or screen capture',
    astPatterns: [
      { type: 'member', property: 'toDataURL' },
      { type: 'member', property: 'getImageData' },
    ],
  },

  // Privacy risks
  {
    category: FindingCategory.PRIVACY_RISK,
    severity: RiskLevel.HIGH,
    description: 'WebRTC peer connection — can expose real IP bypassing proxies/VPNs',
    astPatterns: [{ type: 'call', callee: 'RTCPeerConnection' }],
  },

  // Navigation hijacking / affiliate redirect
  {
    category: FindingCategory.INJECTION,
    severity: RiskLevel.MEDIUM,
    description: 'Modifies current tab URL — potential forced redirect or affiliate hijacking',
    astPatterns: [{ type: 'call', callee: 'chrome.tabs.update' }],
  },

  // Dropper — initiates file downloads to the local filesystem
  {
    category: FindingCategory.DROPPER,
    severity: RiskLevel.CRITICAL,
    description: 'Initiates a file download to the local filesystem',
    astPatterns: [{ type: 'call', callee: 'chrome.downloads.download' }],
  },

  // Exfiltration
  {
    category: FindingCategory.EXFILTRATION,
    severity: RiskLevel.MEDIUM,
    description: 'Communicates with external servers',
    astPatterns: [
      { type: 'call', callee: 'fetch' },
      { type: 'call', callee: 'XMLHttpRequest' },
      { type: 'member', property: 'XMLHttpRequest' },
    ],
  },
  {
    category: FindingCategory.EXFILTRATION,
    severity: RiskLevel.CRITICAL,
    description: 'Uses navigator.sendBeacon for data exfiltration',
    astPatterns: [{ type: 'call', callee: 'navigator.sendBeacon' }],
  },

  // Persistence
  {
    category: FindingCategory.PERSISTENCE,
    severity: RiskLevel.MEDIUM,
    description: 'Uses chrome.storage for local persistence',
    astPatterns: [
      { type: 'call', callee: 'chrome.storage.local.set' },
      { type: 'call', callee: 'chrome.storage.local.get' },
      { type: 'call', callee: 'chrome.storage.sync.set' },
    ],
  },
  {
    category: FindingCategory.PERSISTENCE,
    severity: RiskLevel.MEDIUM,
    description: 'Creates alarms for background execution',
    astPatterns: [{ type: 'call', callee: 'chrome.alarms.create' }],
  },
  {
    category: FindingCategory.PERSISTENCE,
    severity: RiskLevel.MEDIUM,
    description: 'Uses setInterval with potential long periods',
    astPatterns: [{ type: 'call', callee: 'setInterval' }],
  },
];
