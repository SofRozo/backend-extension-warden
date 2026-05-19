import type {
  FileRole,
  HallazgoCodigo,
  PreprocessorOutput,
  UserRiskSummaryId,
  UserRiskSummaryItem,
  UserRiskStatus,
  VerdictedDomainFinding,
  VerdictedStaticFinding,
} from '../../common/interfaces/analysis.interfaces.js';

/**
 * One call site of a chrome.* API. The evaluators use this to distinguish
 * "declared but not used" (capacidad) from "actually invoked from this file"
 * (sospechoso). Without it the evaluators only saw permissions, not usage,
 * and inflated capabilities to "sospechoso" purely from the manifest.
 */
export interface ChromeApiCallSite {
  /** e.g. 'chrome.tabs.query', 'chrome.scripting.executeScript' */
  api: string;
  /** First segment after `chrome.` — used to match against declared permissions. */
  permission: string;
  filePath: string;
  fileRole: FileRole;
  line: number;
}

export interface UserRiskContext {
  preprocessed: PreprocessorOutput;
  positives: VerdictedStaticFinding[];
  domainFindings: VerdictedDomainFinding[];
  perms: Set<string>;
  broadHost: boolean;
  hasContentScript: boolean;
  /** All chrome.* call sites in non-library files. */
  apiCalls: ChromeApiCallSite[];
  /** Permissions actually invoked in code (root key, e.g. 'tabs', 'scripting'). */
  usedPermissions: Set<string>;
  /** Permissions declared in manifest but never invoked anywhere in code. */
  unusedPermissions: Set<string>;
  evidenceByCategory: Map<UserRiskSummaryId, string[]>;
  triggeredRulesByCategory: Map<UserRiskSummaryId, string[]>;
  cwsCategory?: string | null;
}

/**
 * Convenience: returns true when at least one call site matches the given
 * api-name regex. Used in evaluators to escalate `capacidad` → `sospechoso`
 * only when there's real usage of the permission, not just a declaration.
 */
export function hasApiCall(
  context: UserRiskContext,
  apiPattern: RegExp,
): boolean {
  return context.apiCalls.some((c) => apiPattern.test(c.api));
}

/**
 * Returns the first call site matching the pattern, or undefined.
 * Useful when the evaluator wants to point at where the API is used.
 */
export function findApiCall(
  context: UserRiskContext,
  apiPattern: RegExp,
): ChromeApiCallSite | undefined {
  return context.apiCalls.find((c) => apiPattern.test(c.api));
}

export type UserRiskCategoryEvaluator = (
  context: UserRiskContext,
) => UserRiskSummaryItem;

export interface UserRiskStaticRule {
  ruleId: string;
  label: string;
  id: UserRiskSummaryId;
  matches: (finding: VerdictedStaticFinding) => boolean;
  evidence: (finding: VerdictedStaticFinding) => string;
}

export function makeItem(
  context: UserRiskContext,
  id: UserRiskSummaryId,
  titulo: string,
  estado: UserRiskStatus,
  resumen: string,
  evidencias: Array<string | false | undefined>,
  preguntas_responde: string[],
  categoryRules?: UserRiskStaticRule[],
): UserRiskSummaryItem {
  const reglasActivadas = uniqueStrings(
    context.triggeredRulesByCategory.get(id) ?? [],
  );
  const coherentEstado: UserRiskStatus =
    estado === 'no_detectado' && reglasActivadas.length > 0
      ? 'capacidad'
      : estado;

  // Collect code-level findings for this category by running the static rules
  // against all positive findings and keeping only those that belong to `id`.
  // Deduplicate by filePath+line+texto to avoid showing the same line twice.
  const FILE_TYPE_LABEL: Record<string, string> = {
    content_script: 'content script',
    background: 'background',
    service_worker: 'service worker',
    popup: 'popup',
    options_ui: 'página de opciones',
    devtools: 'devtools page',
    sandbox: 'sandbox page',
    override_page: 'override page',
    side_panel: 'side panel',
    library: 'librería',
    unknown: 'archivo',
    manifest: 'manifest',
  };
  const seen = new Set<string>();
  const hallazgos_codigo: HallazgoCodigo[] = [];
  for (const finding of context.positives) {
    for (const rule of (categoryRules ?? []).filter((r) => r.id === id)) {
      if (!rule.matches(finding)) continue;
      const texto = rule.evidence(finding);
      const key = `${finding.filePath}:${finding.line}:${texto}`;
      if (seen.has(key)) continue;
      seen.add(key);
      hallazgos_codigo.push({
        filePath: finding.filePath,
        line: finding.line,
        fileType: FILE_TYPE_LABEL[finding.fileType] ?? finding.fileType,
        texto,
        codeSnippet: finding.codeSnippet?.slice(0, 120) ?? undefined,
      });
    }
  }

  return {
    id,
    titulo,
    estado: coherentEstado,
    resumen,
    evidencias: uniqueStrings([
      ...evidencias.filter((x): x is string => Boolean(x)),
      ...(context.evidenceByCategory.get(id) ?? []),
    ]).slice(0, 5),
    reglas_activadas: reglasActivadas,
    preguntas_responde,
    hallazgos_codigo: hallazgos_codigo.slice(0, 20),
  };
}

export function hasFinding(
  context: UserRiskContext,
  discoveryType: string,
  detailPattern?: RegExp,
): boolean {
  return context.positives.some(
    (finding) =>
      finding.discoveryType === discoveryType &&
      (!detailPattern || detailPattern.test(finding.detail)),
  );
}

export function hasDetail(
  context: UserRiskContext,
  detailPattern: RegExp,
): boolean {
  return context.positives.some((finding) =>
    detailPattern.test(finding.detail),
  );
}

export function uniqueStrings(values: string[]): string[] {
  return [...new Set(values)];
}
