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

// Internal contract — consumed only by StaticAnalysisService which translates
// AstFinding/AstSelector into PreprocessingFinding entries for resultado1.
export interface AstFinding {
  category: FindingCategory;
  pattern: string;
  description: string;
  severity: RiskLevel;
  location: { file: string; line: number; column: number };
  codeSnippet?: string;
}

export interface AstSelector {
  selector: string;
  method: string;
  file: string;
  line: number;
}

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

    let ast: ReturnType<typeof parser.parse>;
    try {
      ast = parser.parse(code, {
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
      return { findings, selectors };
    }

    try {
      traverse(ast, {
        CallExpression: (nodePath) => {
          const node = nodePath.node;
          this.checkCallExpression(node, filename, findings, selectors);
        },
        MemberExpression: (nodePath) => {
          const node = nodePath.node;
          const isWriteTarget =
            t.isAssignmentExpression(nodePath.parent) &&
            nodePath.parent.left === node;
          this.checkMemberExpression(node, filename, findings, isWriteTarget);
        },
        AssignmentExpression: (nodePath) => {
          const node = nodePath.node;
          this.checkAssignment(node, filename, findings);
        },
      });
    } catch (err) {
      this.logger.warn(
        `AST traversal error for ${filename}: ${err instanceof Error ? err.message : String(err)}`,
        'AstParserService',
      );
    }

    return { findings, selectors };
  }

  detectDataFlow(code: string, filename: string): StaticFinding[] {
    const findings: StaticFinding[] = [];
    const lines = code.split('\n');

    // Pass 1: collect variables assigned from page data sources (taint sources)
    const SOURCE_RE =
      /(?:var|let|const)\s+(\w+)\s*=\s*(?:document\.querySelector(?:All)?|document\.getElementById|document\.getElementsBy\w+|document\.cookie|localStorage\.getItem|sessionStorage\.getItem)/;
    const taintedVars = new Map<string, number>(); // varName → source line (1-indexed)

    for (let i = 0; i < lines.length; i++) {
      const m = SOURCE_RE.exec(lines[i]);
      if (m) taintedVars.set(m[1], i + 1);
    }

    if (taintedVars.size === 0) return findings;

    // Pass 2: find network sinks and check if tainted vars appear in context window
    const SINK_RE =
      /\bfetch\s*\(|new\s+XMLHttpRequest\b|\.send\s*\(|navigator\.sendBeacon\s*\(/;
    const CONTEXT_WINDOW = 15;
    const reported = new Set<string>();

    for (let i = 0; i < lines.length; i++) {
      if (!SINK_RE.test(lines[i])) continue;

      const contextStart = Math.max(0, i - CONTEXT_WINDOW);
      const context = lines.slice(contextStart, i + 1).join('\n');

      for (const [varName, sourceLine] of taintedVars) {
        const key = `${varName}:${i}`;
        if (reported.has(key)) continue;
        if (new RegExp(`\\b${varName}\\b`).test(context)) {
          reported.add(key);
          findings.push({
            category: FindingCategory.EXFILTRATION,
            pattern: 'data_flow',
            description: `Page data captured in '${varName}' (line ${sourceLine}) reaches network sink`,
            severity: RiskLevel.CRITICAL,
            location: { file: filename, line: i + 1, column: 0 },
          });
        }
      }
    }

    return findings;
  }

  private checkCallExpression(
    node: t.CallExpression,
    filename: string,
    findings: StaticFinding[],
    selectors: DomSelector[],
  ): void {
    const calleeName = this.getCalleeName(node.callee);
    if (!calleeName) return;

    // Check for DOM selectors
    this.extractDomSelectors(node, calleeName, filename, selectors);

    // Check addEventListener patterns
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
                  astPattern.arguments[0],
                  filename,
                  node,
                ),
              );
            }
          }
        }
      }
      return;
    }

    // Check call patterns
    for (const pattern of RISK_PATTERNS) {
      for (const astPattern of pattern.astPatterns) {
        if (astPattern.type !== 'call') continue;
        if (!astPattern.callee) continue;

        if (this.matchesCallee(calleeName, astPattern.callee)) {
          if (astPattern.arguments && astPattern.arguments.length > 0) {
            const firstArg = node.arguments[0];
            if (
              t.isStringLiteral(firstArg) &&
              astPattern.arguments.some((a) => firstArg.value.includes(a))
            ) {
              findings.push(
                this.createFinding(pattern, calleeName, filename, node),
              );
            }
          } else {
            findings.push(
              this.createFinding(pattern, calleeName, filename, node),
            );
          }
        }
      }
    }
  }

  private checkMemberExpression(
    node: t.MemberExpression,
    filename: string,
    findings: StaticFinding[],
    isWriteTarget = false,
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

        // el.textContent = 'foo' and el.innerText = 'foo' are writes — setting UI text,
        // not reading page content. Skip to avoid false positives.
        if (
          isWriteTarget &&
          pattern.category === FindingCategory.DATA_THEFT &&
          (propertyName === 'textContent' || propertyName === 'innerText')
        )
          continue;

        findings.push(
          this.createFinding(
            pattern,
            `${objectName || '?'}.${propertyName}`,
            filename,
            node,
          ),
        );
      }
    }
  }

  private checkAssignment(
    node: t.AssignmentExpression,
    filename: string,
    findings: StaticFinding[],
  ): void {
    if (!t.isMemberExpression(node.left)) return;
    const propertyName = t.isIdentifier(node.left.property)
      ? node.left.property.name
      : null;
    if (!propertyName) return;

    for (const pattern of RISK_PATTERNS) {
      for (const astPattern of pattern.astPatterns) {
        if (astPattern.type !== 'assignment') continue;
        if (astPattern.property !== propertyName) continue;

        findings.push(
          this.createFinding(pattern, propertyName, filename, node),
        );
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
      if (this.matchesCallee(calleeName, method)) {
        const firstArg = node.arguments[0];
        if (t.isStringLiteral(firstArg)) {
          selectors.push({
            selector: firstArg.value,
            method,
            file: filename,
            line: node.loc?.start.line || 0,
          });
        }
      }
    }
  }

  private getCalleeName(
    callee: t.Expression | t.V8IntrinsicIdentifier,
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

  private createFinding(
    pattern: RiskPattern,
    matchedPattern: string,
    filename: string,
    node: t.Node,
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
    };
  }
}
