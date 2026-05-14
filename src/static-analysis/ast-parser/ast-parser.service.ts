import { Injectable } from '@nestjs/common';
import * as parser from '@babel/parser';
import _traverse from '@babel/traverse';
import * as t from '@babel/types';
import { StructuredLogger } from '../../common/logger/logger.service.js';
import { RISK_PATTERNS, type RiskPattern } from '../patterns/risk-patterns.js';
import {
  FindingCategory,
  RiskLevel,
} from '../../common/enums/risk-level.enum.js';

export interface AstFinding {
  category: FindingCategory;
  pattern: string;
  description: string;
  severity: RiskLevel;
  location: { file: string; line: number; column: number };
  codeSnippet?: string;
  confidence?: number;
}

export interface AstSelector {
  selector: string;
  method: string;
  file: string;
  line: number;
}

type RemoteResourceContact = {
  domain: string;
  line: number;
  kind: 'script' | 'iframe';
};

type StaticFinding = AstFinding;
type DomSelector = AstSelector;

const traverse =
  typeof _traverse === 'function'
    ? _traverse
    : (_traverse as unknown as { default: typeof _traverse }).default;

@Injectable()
export class AstParserService {
  constructor(private readonly logger: StructuredLogger) {}

  parseFile(
    code: string,
    filename: string,
  ): { findings: StaticFinding[]; selectors: DomSelector[] } {
    const findings: StaticFinding[] = [];
    const selectors: DomSelector[] = [];
    const ast = this.parse(code, filename);
    if (!ast) return { findings, selectors };
    const remoteResources = this.extractRemoteResourceContacts(code, filename);

    try {
      traverse(ast, {
        CallExpression: (nodePath) => {
          this.checkCallExpression(
            nodePath.node,
            filename,
            findings,
            selectors,
            code,
          );
          this.checkStringArgumentSignals(
            nodePath.node,
            filename,
            findings,
            code,
          );
        },
        NewExpression: (nodePath) => {
          this.checkNewExpression(nodePath.node, filename, findings, code);
        },
        MemberExpression: (nodePath) => {
          const isWriteTarget =
            t.isAssignmentExpression(nodePath.parent) &&
            nodePath.parent.left === nodePath.node;
          this.checkMemberExpression(
            nodePath.node,
            filename,
            findings,
            isWriteTarget,
            code,
          );
        },
        AssignmentExpression: (nodePath) => {
          this.checkAssignment(nodePath.node, filename, findings, code);
        },
        StringLiteral: (nodePath) => {
          this.checkCredentialLiteral(nodePath.node, filename, findings, code);
        },
        TemplateLiteral: (nodePath) => {
          this.checkCredentialTemplate(nodePath.node, filename, findings, code);
        },
      });

      for (const resource of remoteResources) {
        findings.push({
          category: FindingCategory.INJECTION,
          pattern: `${resource.kind}.src remote`,
          description: `Dynamically loads a remote ${resource.kind} resource from ${resource.domain}`,
          severity:
            resource.kind === 'script' ? RiskLevel.CRITICAL : RiskLevel.HIGH,
          location: {
            file: filename,
            line: resource.line,
            column: 0,
          },
          confidence: resource.kind === 'script' ? 0.92 : 0.84,
        });
      }
    } catch (err) {
      this.logger.warn(
        `AST traversal error for ${filename}: ${err instanceof Error ? err.message : String(err)}`,
        'AstParserService',
      );
    }

    return { findings, selectors };
  }

  /**
   * Extracts ONLY domains that appear as string-literal arguments to a network
   * sink (fetch, XMLHttpRequest, WebSocket, sendBeacon, etc.). Critically,
   * URLs in `window.open()`, `chrome.tabs.create()`, `location.href = ...`
   * etc. are NOT included — those open a browser tab and are a navigation /
   * link affordance, not a network contact from the extension. Used by the
   * static-analysis layer to decide which domains end up in
   * `resultado2_priority` (worth visiting with Stagehand).
   */
  extractContactedDomains(
    code: string,
    filename: string,
  ): Array<{ domain: string; line: number }> {
    const out: Array<{ domain: string; line: number }> = [];
    const seen = new Set<string>();
    const ast = this.parse(code, filename);
    if (!ast) return out;
    const stringConstants = this.collectStringConstants(ast);
    const xhrVars = new Set<string>();

    const pushDomain = (raw: string, line: number) => {
      const host = this.extractHostFromString(raw);
      if (!host) return;
      const key = `${host}:${line}`;
      if (seen.has(key)) return;
      seen.add(key);
      out.push({ domain: host, line });
    };

    const extractFromArg = (arg: t.Node, line: number): void => {
      const resolved = this.resolveStringExpression(arg, stringConstants);
      if (resolved) pushDomain(resolved, line);
    };

    try {
      traverse(ast, {
        VariableDeclarator: (nodePath) => {
          if (
            t.isIdentifier(nodePath.node.id) &&
            t.isNewExpression(nodePath.node.init) &&
            this.getCalleeName(nodePath.node.init.callee) === 'XMLHttpRequest'
          ) {
            xhrVars.add(nodePath.node.id.name);
          }
        },
        AssignmentExpression: (nodePath) => {
          if (
            t.isIdentifier(nodePath.node.left) &&
            t.isNewExpression(nodePath.node.right) &&
            this.getCalleeName(nodePath.node.right.callee) === 'XMLHttpRequest'
          ) {
            xhrVars.add(nodePath.node.left.name);
          }
        },
        CallExpression: (nodePath) => {
          const callee = this.getCalleeName(nodePath.node.callee);
          const line = nodePath.node.loc?.start.line ?? 0;

          if (this.isXhrOpenCall(nodePath.node, xhrVars)) {
            const urlArg =
              nodePath.node.arguments[1] ?? nodePath.node.arguments[0];
            if (urlArg && t.isExpression(urlArg)) extractFromArg(urlArg, line);
            return;
          }

          if (!callee || !this.isNetworkSink(callee)) return;
          for (const arg of nodePath.node.arguments) {
            if (t.isExpression(arg)) extractFromArg(arg, line);
          }
        },
        NewExpression: (nodePath) => {
          const callee = this.getCalleeName(nodePath.node.callee);
          if (callee !== 'WebSocket' && callee !== 'EventSource') return;
          const line = nodePath.node.loc?.start.line ?? 0;
          for (const arg of nodePath.node.arguments) {
            if (t.isExpression(arg)) extractFromArg(arg, line);
          }
        },
      });

      for (const resource of this.extractRemoteResourceContacts(
        code,
        filename,
      )) {
        pushDomain(`https://${resource.domain}`, resource.line);
      }
    } catch (err) {
      this.logger.warn(
        `AST extractContactedDomains error for ${filename}: ${err instanceof Error ? err.message : String(err)}`,
        'AstParserService',
      );
    }

    return out;
  }

  /** Parses a string that may be a full URL or a bare host and returns the host.
   *  Supports http(s), ws(s) and bare hosts. Returns null for relative paths or
   *  empty/junk input. */
  private extractHostFromString(raw: string): string | null {
    const trimmed = raw.trim();
    if (!trimmed) return null;
    // Full URL with scheme — covers https://, wss://, etc.
    const urlMatch = /^[a-z][a-z0-9+.-]*:\/\/([a-zA-Z0-9][-a-zA-Z0-9.]*)/i.exec(
      trimmed,
    );
    if (urlMatch) {
      const host = urlMatch[1].toLowerCase();
      // Filter out XML/SVG namespaces which are often found in code but are not network contacts
      if (
        host === 'www.w3.org' ||
        host === 'xml.org' ||
        host === 'schemas.xmlsoap.org'
      )
        return null;
      return host;
    }
    // Bare host like "api.example.com" or "example.com/path"
    const hostMatch =
      /^([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)(?:[/?#:]|$)/.exec(
        trimmed,
      );
    if (hostMatch) return hostMatch[1].toLowerCase();
    return null;
  }

  /**
   * Intra-file taint analysis: traces sensitive data sources (cookies, password
   * fields, browser history, identity tokens, storage) to network/messaging
   * sinks (fetch, sendBeacon, WebSocket, chrome.runtime.sendMessage, etc.).
   *
   * Tracks taint through:
   *  - Variable declarations          → `const x = document.cookie`
   *  - Plain assignments              → `x = document.cookie`
   *  - Member writes                  → `obj.token = document.cookie` taints `obj`
   *  - Destructuring                  → `const { token } = response` taints `token`
   *  - Promise callbacks              → `chrome.cookies.getAll().then(c => …)` taints `c`
   *  - await expressions              → `await chrome.cookies.getAll()` flows through
   *  - Member reads on tainted bases  → `tainted.foo` still flagged at sink
   *  - JSON.stringify / Array / Object wrappers around tainted values
   */
  detectDataFlow(code: string, filename: string): StaticFinding[] {
    const findings: StaticFinding[] = [];
    const ast = this.parse(code, filename);
    if (!ast) return findings;

    const taintedVars = new Map<string, { line: number; source: string }>();
    const xhrVars = new Set<string>();
    const reported = new Set<string>();

    const markIdent = (name: string, source: string, line: number) => {
      taintedVars.set(name, { source, line });
    };
    const markIfTainted = (name: string, expr: t.Node | null | undefined) => {
      if (!expr) return;
      const source = this.sourceDescription(expr, taintedVars);
      if (source) markIdent(name, source, expr.loc?.start.line ?? 0);
    };

    const emitFlow = (
      callee: string,
      source: string,
      node: t.Node,
      sinkLabel: string,
      confidence: number,
    ) => {
      const line = node.loc?.start.line ?? 0;
      const key = `${callee}:${source}:${line}`;
      if (reported.has(key)) return;
      reported.add(key);
      findings.push({
        category: FindingCategory.EXFILTRATION,
        pattern: 'data_flow',
        description: `${source} flows into ${sinkLabel}`,
        severity: RiskLevel.CRITICAL,
        location: { file: filename, line, column: node.loc?.start.column ?? 0 },
        codeSnippet: this.snippetForNode(code, node),
        confidence,
      });
    };

    traverse(ast, {
      VariableDeclarator: (nodePath) => {
        const init = nodePath.node.init;
        if (!init) return;
        const idNode = nodePath.node.id;
        if (
          t.isIdentifier(idNode) &&
          t.isNewExpression(init) &&
          this.getCalleeName(init.callee) === 'XMLHttpRequest'
        ) {
          xhrVars.add(idNode.name);
        }
        // Simple: const x = source
        if (t.isIdentifier(idNode)) {
          markIfTainted(idNode.name, init);
          return;
        }
        // Destructuring: const { token } = source  OR  const [a] = source
        const source = this.sourceDescription(init, taintedVars);
        if (!source) return;
        this.markDestructured(
          idNode,
          source,
          init.loc?.start.line ?? 0,
          taintedVars,
        );
      },
      AssignmentExpression: (nodePath) => {
        const left = nodePath.node.left;
        const right = nodePath.node.right;
        // x = source
        if (t.isIdentifier(left)) {
          if (
            t.isNewExpression(right) &&
            this.getCalleeName(right.callee) === 'XMLHttpRequest'
          ) {
            xhrVars.add(left.name);
          }
          markIfTainted(left.name, right);
          return;
        }
        // obj.foo = source  → mark the root object as tainted, so a later
        // `fetch(url, obj)` still flags. This is the common "payload-building"
        // pattern: `payload.token = document.cookie; fetch(url, payload);`
        if (t.isMemberExpression(left)) {
          const objName = this.rootObjectName(left);
          if (!objName) return;
          const source = this.sourceDescription(right, taintedVars);
          if (source) markIdent(objName, source, right.loc?.start.line ?? 0);
        }
      },
      CallExpression: (nodePath) => {
        // First, taint callback parameters of sensitive-source promises:
        // chrome.cookies.getAll().then(cookies => fetch(url, cookies))
        this.taintPromiseCallback(nodePath.node, taintedVars);

        const callee = this.getCalleeName(nodePath.node.callee);
        if (!callee) return;

        // Sink check (network/messaging)
        if (this.isNetworkSink(callee) || this.isInternalMessageSink(callee)) {
          for (const arg of nodePath.node.arguments) {
            if (!t.isExpression(arg) && !t.isSpreadElement(arg)) continue;
            const source = this.sourceDescription(arg, taintedVars);
            if (!source) continue;
            emitFlow(
              callee,
              source,
              nodePath.node,
              this.isInternalMessageSink(callee)
                ? `extension message sink ${callee}`
                : `network sink ${callee}`,
              this.isInternalMessageSink(callee) ? 0.78 : 0.9,
            );
          }
        }

        if (this.isXhrOpenCall(nodePath.node, xhrVars)) {
          for (const arg of nodePath.node.arguments) {
            if (!t.isExpression(arg) && !t.isSpreadElement(arg)) continue;
            const source = this.sourceDescription(arg, taintedVars);
            if (!source) continue;
            emitFlow(
              'XMLHttpRequest.open',
              source,
              nodePath.node,
              'XMLHttpRequest URL construction',
              0.84,
            );
          }
        }
      },
      NewExpression: (nodePath) => {
        const callee = this.getCalleeName(nodePath.node.callee);
        if (callee !== 'WebSocket' && callee !== 'EventSource') return;
        for (const arg of nodePath.node.arguments) {
          if (!t.isExpression(arg) && !t.isSpreadElement(arg)) continue;
          const source = this.sourceDescription(arg, taintedVars);
          if (!source) continue;
          emitFlow(
            callee,
            source,
            nodePath.node,
            `${callee} constructor`,
            0.88,
          );
        }
      },
    });

    return findings;
  }

  /**
   * Taints simple destructuring patterns at declaration time.
   * Handles ObjectPattern, ArrayPattern, RestElement, and nested patterns.
   */
  private markDestructured(
    pattern: t.Node,
    source: string,
    line: number,
    taintedVars: Map<string, { line: number; source: string }>,
  ): void {
    if (t.isObjectPattern(pattern)) {
      for (const prop of pattern.properties) {
        if (t.isObjectProperty(prop)) {
          if (t.isIdentifier(prop.value)) {
            taintedVars.set(prop.value.name, { source, line });
          } else if (
            t.isObjectPattern(prop.value) ||
            t.isArrayPattern(prop.value)
          ) {
            this.markDestructured(prop.value, source, line, taintedVars);
          }
        } else if (t.isRestElement(prop) && t.isIdentifier(prop.argument)) {
          taintedVars.set(prop.argument.name, { source, line });
        }
      }
      return;
    }
    if (t.isArrayPattern(pattern)) {
      for (const el of pattern.elements) {
        if (!el) continue;
        if (t.isIdentifier(el)) {
          taintedVars.set(el.name, { source, line });
        } else if (t.isObjectPattern(el) || t.isArrayPattern(el)) {
          this.markDestructured(el, source, line, taintedVars);
        } else if (t.isRestElement(el) && t.isIdentifier(el.argument)) {
          taintedVars.set(el.argument.name, { source, line });
        }
      }
    }
  }

  /**
   * Walks `obj.a.b.c` and returns the leftmost identifier name (`obj`).
   * Used so that `payload.token = document.cookie` taints `payload`.
   */
  private rootObjectName(node: t.Node): string | null {
    if (t.isIdentifier(node)) return node.name;
    if (t.isMemberExpression(node)) return this.rootObjectName(node.object);
    return null;
  }

  /**
   * Detects the pattern `<sensitive-source>().then(param => …)` and taints
   * the callback's first parameter. Without this, any code that fetches
   * cookies/history via a Promise API escapes the taint tracker.
   */
  private taintPromiseCallback(
    call: t.CallExpression,
    taintedVars: Map<string, { line: number; source: string }>,
  ): void {
    if (!t.isMemberExpression(call.callee)) return;
    const propName = t.isIdentifier(call.callee.property)
      ? call.callee.property.name
      : null;
    if (propName !== 'then') return;

    const source = this.sensitiveCallSource(call.callee.object, taintedVars);
    if (!source) return;

    const cb = call.arguments[0];
    if (!cb) return;
    if (!t.isArrowFunctionExpression(cb) && !t.isFunctionExpression(cb)) return;
    const firstParam = cb.params[0];
    if (!firstParam) return;

    const line = call.loc?.start.line ?? 0;
    if (t.isIdentifier(firstParam)) {
      taintedVars.set(firstParam.name, { source, line });
    } else {
      this.markDestructured(firstParam, source, line, taintedVars);
    }
  }

  /**
   * Returns a source description if the given node is a call to a sensitive
   * browser/extension API (chrome.cookies.*, chrome.history.*, etc.), else null.
   * Used when the Promise's receiver is itself a sensitive call.
   */
  private sensitiveCallSource(
    node: t.Node,
    taintedVars: Map<string, { line: number; source: string }>,
  ): string | null {
    if (!t.isCallExpression(node)) {
      // Allow `expr` to be an awaited expression
      if (t.isAwaitExpression(node)) {
        return this.sensitiveCallSource(node.argument, taintedVars);
      }
      return null;
    }
    const callee = this.getCalleeName(node.callee);
    if (!callee) return null;
    if (
      /^(chrome\.cookies|chrome\.history|chrome\.tabs\.query|chrome\.tabs\.captureVisibleTab|chrome\.storage|chrome\.identity|chrome\.bookmarks|chrome\.downloads\.search|chrome\.management|chrome\.topSites|chrome\.sessions|chrome\.scripting\.executeScript)/.test(
        callee,
      )
    ) {
      return `sensitive API source ${callee}`;
    }
    // Chained .then(): recurse into the upstream call.
    if (t.isMemberExpression(node.callee)) {
      const propName = t.isIdentifier(node.callee.property)
        ? node.callee.property.name
        : null;
      if (
        propName === 'then' ||
        propName === 'catch' ||
        propName === 'finally'
      ) {
        return this.sensitiveCallSource(node.callee.object, taintedVars);
      }
    }
    // Resolve via tainted vars when the receiver was previously stored
    const receiver = t.isMemberExpression(node.callee)
      ? node.callee.object
      : null;
    if (receiver && t.isIdentifier(receiver)) {
      return taintedVars.get(receiver.name)?.source ?? null;
    }
    return null;
  }

  private parse(
    code: string,
    filename: string,
  ): ReturnType<typeof parser.parse> | null {
    try {
      return parser.parse(code, {
        sourceType: 'unambiguous',
        plugins: [
          'jsx',
          'typescript',
          'dynamicImport',
          'optionalChaining',
          'nullishCoalescingOperator',
        ],
        errorRecovery: true,
      });
    } catch (err) {
      this.logger.warn(
        `AST parse failed for ${filename}: ${err instanceof Error ? err.message : String(err)}`,
        'AstParserService',
      );
      return null;
    }
  }

  private checkCallExpression(
    node: t.CallExpression,
    filename: string,
    findings: StaticFinding[],
    selectors: DomSelector[],
    code: string,
  ): void {
    const calleeName = this.getCalleeName(node.callee);
    if (!calleeName) return;
    this.extractDomSelectors(node, calleeName, filename, selectors);

    if (
      calleeName.endsWith('.addEventListener') ||
      calleeName === 'addEventListener'
    ) {
      const firstArg = node.arguments[0];
      if (t.isStringLiteral(firstArg)) {
        for (const pattern of RISK_PATTERNS) {
          for (const astPattern of pattern.astPatterns) {
            if (
              astPattern.type === 'event_listener' &&
              astPattern.arguments?.includes(firstArg.value)
            ) {
              findings.push(
                this.createFinding(
                  pattern,
                  firstArg.value,
                  filename,
                  node,
                  code,
                ),
              );
            }
          }
        }
      }
      return;
    }

    for (const pattern of RISK_PATTERNS) {
      for (const astPattern of pattern.astPatterns) {
        if (astPattern.type !== 'call' || !astPattern.callee) continue;
        if (!this.matchesCallee(calleeName, astPattern.callee)) continue;
        if (astPattern.arguments?.length) {
          const firstArg = node.arguments[0];
          if (
            t.isStringLiteral(firstArg) &&
            astPattern.arguments.some((a) => firstArg.value.includes(a))
          ) {
            findings.push(
              this.createFinding(pattern, calleeName, filename, node, code),
            );
          }
        } else {
          findings.push(
            this.createFinding(pattern, calleeName, filename, node, code),
          );
        }
      }
    }

    if (this.isNetworkSink(calleeName)) {
      findings.push({
        category: FindingCategory.EXFILTRATION,
        pattern: calleeName,
        description: `Network sink ${calleeName} can exfiltrate extension or page data`,
        severity: calleeName === 'fetch' ? RiskLevel.MEDIUM : RiskLevel.HIGH,
        location: {
          file: filename,
          line: node.loc?.start.line || 0,
          column: node.loc?.start.column || 0,
        },
        codeSnippet: this.snippetForNode(code, node),
        confidence: 0.75,
      });
    }

    if (this.isInternalMessageSink(calleeName)) {
      findings.push({
        category: FindingCategory.EXFILTRATION,
        pattern: calleeName,
        description: `Extension messaging sink ${calleeName} can move page data into privileged contexts`,
        severity: RiskLevel.MEDIUM,
        location: {
          file: filename,
          line: node.loc?.start.line || 0,
          column: node.loc?.start.column || 0,
        },
        codeSnippet: this.snippetForNode(code, node),
        confidence: 0.62,
      });
    }

    if (
      (calleeName === 'setTimeout' || calleeName === 'setInterval') &&
      t.isStringLiteral(node.arguments[0])
    ) {
      findings.push({
        category: FindingCategory.INJECTION,
        pattern: `${calleeName}(string)`,
        description: 'Executes JavaScript from a string timer argument',
        severity: RiskLevel.HIGH,
        location: {
          file: filename,
          line: node.loc?.start.line || 0,
          column: node.loc?.start.column || 0,
        },
        codeSnippet: this.snippetForNode(code, node),
        confidence: 0.9,
      });
    }
  }

  private checkNewExpression(
    node: t.NewExpression,
    filename: string,
    findings: StaticFinding[],
    code: string,
  ): void {
    const callee = this.getCalleeName(node.callee);
    if (callee === 'Function') {
      findings.push({
        category: FindingCategory.INJECTION,
        pattern: 'new Function',
        description: 'Creates executable code dynamically',
        severity: RiskLevel.CRITICAL,
        location: {
          file: filename,
          line: node.loc?.start.line || 0,
          column: node.loc?.start.column || 0,
        },
        codeSnippet: this.snippetForNode(code, node),
        confidence: 0.95,
      });
    }
    if (callee === 'WebSocket' || callee === 'EventSource') {
      findings.push({
        category: FindingCategory.EXFILTRATION,
        pattern: callee,
        description: `${callee} opens a persistent external communication channel`,
        severity: RiskLevel.HIGH,
        location: {
          file: filename,
          line: node.loc?.start.line || 0,
          column: node.loc?.start.column || 0,
        },
        codeSnippet: this.snippetForNode(code, node),
        confidence: 0.82,
      });
    }
  }

  private checkMemberExpression(
    node: t.MemberExpression,
    filename: string,
    findings: StaticFinding[],
    isWriteTarget: boolean,
    code: string,
  ): void {
    const propertyName = t.isIdentifier(node.property)
      ? node.property.name
      : t.isStringLiteral(node.property)
        ? node.property.value
        : null;
    if (!propertyName) return;
    const objectName = this.getObjectName(node.object);

    for (const pattern of RISK_PATTERNS) {
      for (const astPattern of pattern.astPatterns) {
        if (astPattern.type !== 'member') continue;
        if (astPattern.property !== propertyName) continue;
        if (astPattern.object && objectName !== astPattern.object) continue;
        if (
          isWriteTarget &&
          pattern.category === FindingCategory.DATA_THEFT &&
          (propertyName === 'textContent' || propertyName === 'innerText')
        ) {
          continue;
        }
        findings.push(
          this.createFinding(
            pattern,
            `${objectName || '?'}.${propertyName}`,
            filename,
            node,
            code,
          ),
        );
      }
    }
  }

  private checkAssignment(
    node: t.AssignmentExpression,
    filename: string,
    findings: StaticFinding[],
    code: string,
  ): void {
    if (!t.isMemberExpression(node.left)) return;
    const propertyName = t.isIdentifier(node.left.property)
      ? node.left.property.name
      : null;
    if (!propertyName) return;

    for (const pattern of RISK_PATTERNS) {
      for (const astPattern of pattern.astPatterns) {
        if (
          astPattern.type === 'assignment' &&
          astPattern.property === propertyName
        ) {
          findings.push(
            this.createFinding(pattern, propertyName, filename, node, code),
          );
        }
      }
    }

    const leftName = this.getCalleeName(node.left);
    if (
      leftName?.endsWith('.src') &&
      this.expressionContainsScript(node.right)
    ) {
      findings.push({
        category: FindingCategory.INJECTION,
        pattern: 'script.src assignment',
        description: 'Assigns a script source dynamically',
        severity: RiskLevel.HIGH,
        location: {
          file: filename,
          line: node.loc?.start.line || 0,
          column: node.loc?.start.column || 0,
        },
        codeSnippet: this.snippetForNode(code, node),
        confidence: 0.82,
      });
    }

    // ── API hooking / monkey-patching detection ────────────────────────────
    // Extensions that replace native browser APIs to intercept traffic or
    // spoof capabilities are highly suspicious. The patterns below catch
    // prototype-level hooks and global replacements.
    if (t.isMemberExpression(node.left)) {
      const fullName = this.getCalleeName(node.left);
      if (fullName) {
        // XHR prototype hooking: XMLHttpRequest.prototype.open/send/setRequestHeader = ...
        if (
          /XMLHttpRequest\.prototype\.(open|send|setRequestHeader)$/.test(
            fullName,
          )
        ) {
          findings.push({
            category: FindingCategory.INTERCEPTION,
            pattern: 'xhr_prototype_hook',
            description: `Monkey-patches ${fullName} — intercepts all XHR traffic on the page`,
            severity: RiskLevel.CRITICAL,
            location: {
              file: filename,
              line: node.loc?.start.line || 0,
              column: node.loc?.start.column || 0,
            },
            codeSnippet: this.snippetForNode(code, node),
            confidence: 0.95,
          });
        }

        // Fetch replacement: window.fetch / self.fetch / globalThis.fetch = ...
        if (
          /\.(fetch)$/.test(fullName) &&
          (t.isFunctionExpression(node.right) ||
            t.isArrowFunctionExpression(node.right))
        ) {
          findings.push({
            category: FindingCategory.INTERCEPTION,
            pattern: 'fetch_hook',
            description: `Replaces ${fullName} — intercepts all fetch() traffic on the page`,
            severity: RiskLevel.CRITICAL,
            location: {
              file: filename,
              line: node.loc?.start.line || 0,
              column: node.loc?.start.column || 0,
            },
            codeSnippet: this.snippetForNode(code, node),
            confidence: 0.94,
          });
        }

        // History API hooking: history.pushState / history.replaceState = ...
        if (
          /history\.(pushState|replaceState)$/.test(fullName) &&
          (t.isFunctionExpression(node.right) ||
            t.isArrowFunctionExpression(node.right))
        ) {
          findings.push({
            category: FindingCategory.INTERCEPTION,
            pattern: 'history_api_hook',
            description: `Replaces ${fullName} — monitors or intercepts navigation state changes`,
            severity: RiskLevel.HIGH,
            location: {
              file: filename,
              line: node.loc?.start.line || 0,
              column: node.loc?.start.column || 0,
            },
            codeSnippet: this.snippetForNode(code, node),
            confidence: 0.85,
          });
        }

        // Geolocation API replacement: navigator.geolocation.getCurrentPosition/watchPosition = ...
        if (
          /navigator\.geolocation\.(getCurrentPosition|watchPosition|clearWatch)$/.test(
            fullName,
          )
        ) {
          findings.push({
            category: FindingCategory.INTERCEPTION,
            pattern: 'geolocation_api_spoof',
            description: `Replaces ${fullName} — can fake or suppress user geolocation`,
            severity: RiskLevel.HIGH,
            location: {
              file: filename,
              line: node.loc?.start.line || 0,
              column: node.loc?.start.column || 0,
            },
            codeSnippet: this.snippetForNode(code, node),
            confidence: 0.92,
          });
        }
      }
    }
  }

  private extractDomSelectors(
    node: t.CallExpression,
    calleeName: string,
    filename: string,
    selectors: DomSelector[],
  ): void {
    const selectorMethods = [
      'document.querySelector',
      'document.querySelectorAll',
      'document.getElementById',
      'document.getElementsByClassName',
      'document.getElementsByTagName',
      'document.getElementsByName',
    ];
    for (const method of selectorMethods) {
      if (
        this.matchesCallee(calleeName, method) &&
        t.isStringLiteral(node.arguments[0])
      ) {
        selectors.push({
          selector: node.arguments[0].value,
          method,
          file: filename,
          line: node.loc?.start.line || 0,
        });
      }
    }
  }

  private checkCredentialLiteral(
    node: t.StringLiteral,
    filename: string,
    findings: StaticFinding[],
    code: string,
  ): void {
    const matched = this.credentialLiteralKeyword(node.value);
    if (!matched) return;
    findings.push({
      category: FindingCategory.DATA_THEFT,
      pattern: `credential string:${matched}`,
      description: `Credential-related string "${matched}" appears in code`,
      severity: RiskLevel.MEDIUM,
      location: {
        file: filename,
        line: node.loc?.start.line || 0,
        column: node.loc?.start.column || 0,
      },
      codeSnippet: this.snippetForNode(code, node),
      confidence: 0.65,
    });
  }

  private checkCredentialTemplate(
    node: t.TemplateLiteral,
    filename: string,
    findings: StaticFinding[],
    code: string,
  ): void {
    const text = node.quasis
      .map((q) => q.value.cooked ?? q.value.raw)
      .join('${}');
    const matched = this.credentialLiteralKeyword(text);
    if (!matched) return;
    findings.push({
      category: FindingCategory.DATA_THEFT,
      pattern: `credential template:${matched}`,
      description: `Credential-related template string "${matched}" appears in code`,
      severity: RiskLevel.MEDIUM,
      location: {
        file: filename,
        line: node.loc?.start.line || 0,
        column: node.loc?.start.column || 0,
      },
      codeSnippet: this.snippetForNode(code, node),
      confidence: 0.65,
    });
  }

  private checkStringArgumentSignals(
    node: t.CallExpression,
    filename: string,
    findings: StaticFinding[],
    code: string,
  ): void {
    const callee = this.getCalleeName(node.callee);
    if (
      !callee ||
      !/(querySelector|querySelectorAll|getElementById|getElementsByName)/.test(
        callee,
      )
    )
      return;
    const firstArg = node.arguments[0];
    if (!t.isStringLiteral(firstArg)) return;
    const matched = this.credentialSelectorKeyword(firstArg.value);
    if (!matched) return;
    findings.push({
      category: FindingCategory.DATA_THEFT,
      pattern: `credential selector:${matched}`,
      description: `DOM selector targets credential-related field "${matched}"`,
      severity: ['password', 'privatekey', 'seed phrase', 'mnemonic'].includes(
        matched,
      )
        ? RiskLevel.CRITICAL
        : RiskLevel.HIGH,
      location: {
        file: filename,
        line: node.loc?.start.line || 0,
        column: node.loc?.start.column || 0,
      },
      codeSnippet: this.snippetForNode(code, node),
      confidence: 0.9,
    });
  }

  private sourceDescription(
    expr: t.Node,
    taintedVars: Map<string, { line: number; source: string }>,
  ): string | null {
    if (t.isIdentifier(expr)) return taintedVars.get(expr.name)?.source ?? null;

    // `await tainted` flows through.
    if (t.isAwaitExpression(expr)) {
      return this.sourceDescription(expr.argument, taintedVars);
    }
    // `tainted as Type`, `tainted!`, `tainted satisfies T` — TS noise, pass through.
    if (
      t.isTSAsExpression(expr) ||
      t.isTSNonNullExpression(expr) ||
      t.isTSSatisfiesExpression(expr) ||
      t.isTSTypeAssertion(expr)
    ) {
      return this.sourceDescription(expr.expression, taintedVars);
    }

    const callee = t.isCallExpression(expr)
      ? this.getCalleeName(expr.callee)
      : null;
    if (callee) {
      if (callee.startsWith('document.cookie.')) return 'document.cookie';
      if (
        /querySelector|querySelectorAll|getElementById|getElementsBy/.test(
          callee,
        )
      )
        return `DOM selection via ${callee}`;
      if (
        /localStorage|getItem|sessionStorage|navigator\.clipboard|chrome\.storage|chrome\.cookies|chrome\.history|chrome\.tabs\.query|chrome\.tabs\.captureVisibleTab|chrome\.identity|chrome\.bookmarks|chrome\.downloads\.search|chrome\.management|chrome\.topSites|chrome\.sessions|GetCookie|GetAllCookies|getCookie|getAllCookies/.test(
          callee,
        )
      )
        return `sensitive API source ${callee}`;
      if (/JSON\.stringify/.test(callee)) {
        // JSON.stringify(tainted) — flow through the argument
        for (const arg of (expr as t.CallExpression).arguments) {
          if (t.isExpression(arg) || t.isSpreadElement(arg)) {
            const src = this.sourceDescription(arg, taintedVars);
            if (src) return src;
          }
        }
      }
    }

    const member = t.isMemberExpression(expr) ? this.getCalleeName(expr) : null;
    if (t.isMemberExpression(expr)) {
      const prop = t.isIdentifier(expr.property)
        ? expr.property.name
        : t.isStringLiteral(expr.property)
          ? expr.property.value
          : null;
      if (
        prop &&
        ['value', 'innerText', 'textContent', 'innerHTML'].includes(prop)
      ) {
        const objectSource = this.sourceDescription(expr.object, taintedVars);
        if (objectSource) return `${objectSource}.${prop}`;
      }
    }
    if (member) {
      if (member === 'document.cookie' || member.startsWith('document.cookie.')) return 'document.cookie';
      if (
        /localStorage|sessionStorage|indexedDB|window\.location|navigator\.clipboard|document\.forms|document\.documentElement|document\.body/.test(
          member,
        )
      )
        return member;
      if (/\.(value|innerText|textContent)$/.test(member))
        return `DOM read ${member}`;
    }
    // Member read on a tainted root: `payload.token` where `payload` is tainted.
    if (t.isMemberExpression(expr)) {
      const root = this.rootObjectName(expr);
      if (root) {
        const tainted = taintedVars.get(root);
        if (tainted) return tainted.source;
      }
    }

    if (t.isTemplateLiteral(expr)) {
      for (const e of expr.expressions) {
        const source = this.sourceDescription(e, taintedVars);
        if (source) return source;
      }
    }
    if (t.isBinaryExpression(expr)) {
      return (
        this.sourceDescription(expr.left, taintedVars) ??
        this.sourceDescription(expr.right, taintedVars)
      );
    }
    if (t.isObjectExpression(expr)) {
      for (const prop of expr.properties) {
        if (t.isObjectProperty(prop)) {
          const source = this.sourceDescription(prop.value, taintedVars);
          if (source) return source;
        } else if (t.isSpreadElement(prop)) {
          const source = this.sourceDescription(prop.argument, taintedVars);
          if (source) return source;
        }
      }
    }
    if (t.isArrayExpression(expr)) {
      for (const el of expr.elements) {
        if (!el) continue;
        if (t.isExpression(el) || t.isSpreadElement(el)) {
          const source = this.sourceDescription(el, taintedVars);
          if (source) return source;
        }
      }
    }
    if (t.isCallExpression(expr)) {
      for (const arg of expr.arguments) {
        if (t.isExpression(arg) || t.isSpreadElement(arg)) {
          const source = this.sourceDescription(arg, taintedVars);
          if (source) return source;
        }
      }
    }
    return null;
  }

  private getCalleeName(
    callee: t.Node | t.V8IntrinsicIdentifier,
  ): string | null {
    if (t.isIdentifier(callee)) return callee.name;
    if (t.isMemberExpression(callee)) {
      const obj = this.getCalleeName(callee.object);
      const prop = t.isIdentifier(callee.property)
        ? callee.property.name
        : t.isStringLiteral(callee.property)
          ? callee.property.value
          : null;
      if (obj && prop) return `${obj}.${prop}`;
      if (prop) return prop;
    }
    return null;
  }

  private getObjectName(node: t.Expression | t.Super): string | null {
    if (t.isIdentifier(node)) return node.name;
    if (t.isMemberExpression(node)) {
      const obj = this.getObjectName(node.object);
      const prop = t.isIdentifier(node.property) ? node.property.name : null;
      if (obj && prop) return `${obj}.${prop}`;
    }
    return null;
  }

  private matchesCallee(actual: string, expected: string): boolean {
    return actual === expected || actual.endsWith(`.${expected}`);
  }

  private isNetworkSink(calleeName: string): boolean {
    return [
      'fetch',
      'axios',
      'axios.get',
      'axios.post',
      'axios.put',
      'axios.patch',
      'axios.request',
      'navigator.sendBeacon',
      'XMLHttpRequest.send',
      'postMessage',
      // 'chrome.runtime.sendMessage',  // Internal IPC
      // 'chrome.tabs.sendMessage',     // Internal IPC
      'chrome.runtime.sendNativeMessage',
      'chrome.runtime.connect',
      'chrome.runtime.connectNative',
      'chrome.identity.launchWebAuthFlow',
      'navigator.serviceWorker.controller.postMessage',
    ].some((sink) => calleeName === sink || calleeName.endsWith(`.${sink}`));
  }

  private isInternalMessageSink(calleeName: string): boolean {
    return [
      // Only channels that can move data out of a content-script/page context
      // are treated as taint sinks. background -> tab messaging is ordinary
      // extension IPC and should not be elevated by itself.
      'chrome.runtime.sendMessage',
      'window.postMessage',
    ].some((sink) => calleeName === sink || calleeName.endsWith(`.${sink}`));
  }

  private isXhrOpenCall(node: t.CallExpression, xhrVars: Set<string>): boolean {
    if (!t.isMemberExpression(node.callee)) return false;
    const prop = t.isIdentifier(node.callee.property)
      ? node.callee.property.name
      : t.isStringLiteral(node.callee.property)
        ? node.callee.property.value
        : null;
    if (prop !== 'open') return false;
    return (
      t.isIdentifier(node.callee.object) && xhrVars.has(node.callee.object.name)
    );
  }

  private collectStringConstants(
    ast: ReturnType<typeof parser.parse>,
  ): Map<string, string> {
    const constants = new Map<string, string>();
    traverse(ast, {
      VariableDeclarator: (nodePath) => {
        if (!t.isIdentifier(nodePath.node.id)) return;
        const init = nodePath.node.init;
        if (!init) return;
        const resolved = this.resolveStringExpression(init, constants);
        if (resolved) constants.set(nodePath.node.id.name, resolved);
      },
    });
    return constants;
  }

  private resolveStringExpression(
    node: t.Node,
    constants: Map<string, string>,
  ): string | null {
    if (t.isStringLiteral(node)) return node.value;
    if (t.isIdentifier(node)) return constants.get(node.name) ?? null;
    if (t.isTemplateLiteral(node)) {
      let text = '';
      for (let i = 0; i < node.quasis.length; i++) {
        text += node.quasis[i].value.cooked ?? node.quasis[i].value.raw;
        const expr = node.expressions[i];
        if (expr) text += this.resolveStringExpression(expr, constants) ?? '';
      }
      return text || null;
    }
    if (t.isBinaryExpression(node) && node.operator === '+') {
      const left = this.resolveStringExpression(node.left, constants);
      const right = this.resolveStringExpression(node.right, constants);
      if (left === null && right === null) return null;
      return `${left ?? ''}${right ?? ''}`;
    }
    if (t.isCallExpression(node)) {
      const callee = this.getCalleeName(node.callee);
      const first = node.arguments[0];
      if (
        callee === 'atob' &&
        first &&
        t.isStringLiteral(first) &&
        /^[A-Za-z0-9+/]+={0,2}$/.test(first.value)
      ) {
        try {
          return Buffer.from(first.value, 'base64').toString('utf-8');
        } catch {
          return null;
        }
      }
    }
    return null;
  }

  private credentialLiteralKeyword(text: string): string | null {
    const lowered = text.toLowerCase();
    const keywords = [
      'password',
      'bearer',
      'access_token',
      'refresh_token',
      'api_key',
      'wallet',
      'seed phrase',
      'mnemonic',
      'privatekey',
      'metamask',
    ];
    return keywords.find((k) => lowered.includes(k)) ?? null;
  }

  private credentialSelectorKeyword(text: string): string | null {
    const lowered = text.toLowerCase();
    const keywords = [
      'password',
      'token',
      'auth',
      'bearer',
      'access_token',
      'refresh_token',
      'wallet',
      'seed phrase',
      'mnemonic',
      'privatekey',
      'metamask',
    ];
    return keywords.find((k) => lowered.includes(k)) ?? null;
  }

  private expressionContainsScript(expr: t.Expression): boolean {
    if (t.isStringLiteral(expr))
      return /\.js(?:\?|$)|^https?:\/\//i.test(expr.value);
    if (t.isTemplateLiteral(expr))
      return /\.js|https?:\/\//i.test(
        expr.quasis.map((q) => q.value.raw).join(''),
      );
    if (t.isBinaryExpression(expr)) {
      return (
        (t.isExpression(expr.left) &&
          this.expressionContainsScript(expr.left)) ||
        (t.isExpression(expr.right) &&
          this.expressionContainsScript(expr.right))
      );
    }
    return false;
  }

  private extractRemoteResourceContacts(
    code: string,
    filename: string,
  ): RemoteResourceContact[] {
    const out: RemoteResourceContact[] = [];
    const seen = new Set<string>();
    const ast = this.parse(code, filename);
    if (!ast) return out;

    const elementVars = new Map<string, 'script' | 'iframe'>();
    const stringConstants = this.collectStringConstants(ast);

    const add = (
      raw: string | null,
      line: number,
      kind: 'script' | 'iframe',
    ) => {
      if (!raw) return;
      const domain = this.extractHostFromString(raw);
      if (!domain) return;
      const key = `${kind}:${domain}:${line}`;
      if (seen.has(key)) return;
      seen.add(key);
      out.push({ domain, line, kind });
    };

    traverse(ast, {
      VariableDeclarator: (nodePath) => {
        if (!t.isIdentifier(nodePath.node.id)) return;
        const tag = this.createdElementTag(nodePath.node.init);
        if (tag === 'script' || tag === 'iframe') {
          elementVars.set(nodePath.node.id.name, tag);
        }
      },
      AssignmentExpression: (nodePath) => {
        if (t.isIdentifier(nodePath.node.left)) {
          const tag = this.createdElementTag(nodePath.node.right);
          if (tag === 'script' || tag === 'iframe') {
            elementVars.set(nodePath.node.left.name, tag);
          }
          return;
        }

        if (!t.isMemberExpression(nodePath.node.left)) return;
        const prop = t.isIdentifier(nodePath.node.left.property)
          ? nodePath.node.left.property.name
          : t.isStringLiteral(nodePath.node.left.property)
            ? nodePath.node.left.property.value
            : null;
        if (prop !== 'src') return;

        const obj = nodePath.node.left.object;
        const tag = t.isIdentifier(obj) ? elementVars.get(obj.name) : null;
        if (tag !== 'script' && tag !== 'iframe') return;

        add(
          this.resolveStringExpression(nodePath.node.right, stringConstants),
          nodePath.node.loc?.start.line ?? 0,
          tag,
        );
      },
    });

    return out;
  }

  private createdElementTag(node: t.Node | null | undefined): string | null {
    if (!node || !t.isCallExpression(node)) return null;
    const callee = this.getCalleeName(node.callee);
    if (callee !== 'document.createElement') return null;
    const first = node.arguments[0];
    return t.isStringLiteral(first) ? first.value.toLowerCase() : null;
  }

  private createFinding(
    pattern: RiskPattern,
    matchedPattern: string,
    filename: string,
    node: t.Node,
    code: string,
  ): StaticFinding {
    return {
      category: pattern.category,
      pattern: matchedPattern,
      description: pattern.description,
      severity: pattern.severity,
      location: {
        file: filename,
        line: node.loc?.start.line || 0,
        column: node.loc?.start.column || 0,
      },
      codeSnippet: this.snippetForNode(code, node),
      confidence: 0.8,
    };
  }

  private snippetForNode(code: string, node: t.Node): string | undefined {
    const line = node.loc?.start.line;
    if (!line) return undefined;
    return code.split('\n')[line - 1]?.trim().slice(0, 240);
  }
}
