import type {
  DynamicVerdictedFinding,
  PreprocessorOutput,
  UserRiskSummaryId,
  UserRiskSummaryItem,
  UserRiskStatus,
  VerdictedDomainFinding,
  VerdictedStaticFinding,
} from '../../common/interfaces/analysis.interfaces.js';

export interface UserRiskContext {
  preprocessed: PreprocessorOutput;
  positives: VerdictedStaticFinding[];
  domainFindings: VerdictedDomainFinding[];
  dynamicFindings: DynamicVerdictedFinding[];
  perms: Set<string>;
  broadHost: boolean;
  hasContentScript: boolean;
  evidenceByCategory: Map<UserRiskSummaryId, string[]>;
  triggeredRulesByCategory: Map<UserRiskSummaryId, string[]>;
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
): UserRiskSummaryItem {
  return {
    id,
    titulo,
    estado,
    resumen,
    evidencias: uniqueStrings([
      ...evidencias.filter((x): x is string => Boolean(x)),
      ...(context.evidenceByCategory.get(id) ?? []),
    ]).slice(0, 5),
    reglas_activadas: uniqueStrings(context.triggeredRulesByCategory.get(id) ?? []),
    preguntas_responde,
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
  return context.positives.some((finding) => detailPattern.test(finding.detail));
}

export function uniqueStrings(values: string[]): string[] {
  return [...new Set(values)];
}
