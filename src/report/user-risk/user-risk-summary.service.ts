import { Injectable } from '@nestjs/common';
import type {
  DynamicVerdictedFinding,
  PreprocessorOutput,
  UserFacingVerdict,
  UserRiskSummaryId,
  UserRiskSummaryItem,
  UserRiskStatus,
  VerdictedDomainFinding,
  VerdictedStaticFinding,
} from '../../common/interfaces/analysis.interfaces.js';
import {
  USER_RISK_CATEGORY_EVALUATORS,
  USER_RISK_STATIC_RULES,
} from './categories/index.js';
import type { ChromeApiCallSite, UserRiskContext } from './types.js';
import { uniqueStrings } from './types.js';

@Injectable()
export class UserRiskSummaryService {
  buildSummary(
    preprocessed: PreprocessorOutput,
    staticFindings: VerdictedStaticFinding[],
    domainFindings: VerdictedDomainFinding[],
    dynamicFindings: DynamicVerdictedFinding[],
  ): UserRiskSummaryItem[] {
    const positives = staticFindings.filter((f) => f.veredicto === 'positivo');
    const suspiciousDynamic = dynamicFindings.filter(
      (f) => f.veredicto === 'maliciosa' || f.veredicto === 'sospechosa',
    );
    const perms = new Set([
      ...preprocessed.manifest.apiPermissions,
      ...preprocessed.manifest.optionalPermissions,
    ]);
    const hostPerms = preprocessed.manifest.hostPermissions ?? [];
    const contentMatches = preprocessed.manifest.contentScripts.flatMap(
      (cs) => cs.matches,
    );

    const apiCalls = this.collectApiCalls(preprocessed);
    const usedPermissions = new Set<string>();
    for (const call of apiCalls) usedPermissions.add(call.permission);
    // unusedPermissions = declared but never invoked. This is the signal that
    // surfaces overprivileged extensions ("pide X pero no lo usa") which the
    // user-risk evaluators previously couldn't see.
    const unusedPermissions = new Set<string>();
    for (const p of perms) {
      if (!usedPermissions.has(p)) unusedPermissions.add(p);
    }

    const context: UserRiskContext = {
      preprocessed,
      positives,
      domainFindings,
      dynamicFindings: suspiciousDynamic,
      perms,
      broadHost: [...hostPerms, ...contentMatches].some((p) =>
        this.isBroadHostPattern(p),
      ),
      hasContentScript: preprocessed.manifest.contentScripts.length > 0,
      apiCalls,
      usedPermissions,
      unusedPermissions,
      evidenceByCategory: this.collectCategoryEvidence(
        preprocessed,
        positives,
        domainFindings,
        suspiciousDynamic,
      ),
      triggeredRulesByCategory: this.collectTriggeredRules(positives),
    };

    const summary = USER_RISK_CATEGORY_EVALUATORS.map((evaluate) =>
      evaluate(context),
    );

    if (suspiciousDynamic.length > 0) {
      summary.unshift({
        id: 'seguimiento_privacidad',
        titulo: 'Comportamiento observado en navegación',
        estado: suspiciousDynamic.some((f) => f.veredicto === 'maliciosa')
          ? 'critico'
          : 'sospechoso',
        resumen:
          'Durante el análisis dinámico se observó comportamiento sospechoso o malicioso.',
        evidencias: suspiciousDynamic.slice(0, 3).map((f) => f.razon),
        preguntas_responde: [
          '¿Qué hizo realmente la extensión durante la prueba?',
        ],
      });
    }

    return summary;
  }

  buildVerdict(summary: UserRiskSummaryItem[]): UserFacingVerdict {
    const critical = summary.filter((item) => item.estado === 'critico');
    const suspicious = summary.filter((item) => item.estado === 'sospechoso');
    const capabilities = summary.filter((item) => item.estado === 'capacidad');

    const criticalIds = new Set(critical.map((item) => item.id));
    const hasDirectAbuse =
      criticalIds.has('captura_credenciales') ||
      criticalIds.has('keylogging') ||
      criticalIds.has('modificacion_paginas') ||
      criticalIds.has('manipulacion_trafico') ||
      critical.some((item) =>
        /dinámico|observó|malicioso|exfiltr/i.test(item.resumen),
      );

    if (hasDirectAbuse) {
      return {
        nivel: 'critico',
        veredicto: 'maliciosa',
        resumen:
          'La extensión muestra señales compatibles con abuso directo de datos o manipulación peligrosa.',
        razones: this.topUserReasons([...critical, ...suspicious], 5),
      };
    }

    if (critical.length > 0 || suspicious.length >= 3) {
      return {
        nivel: 'alto',
        veredicto: 'sospechosa',
        resumen:
          'La extensión combina varias capacidades sensibles. No basta con decir que es maliciosa, pero sí requiere cautela.',
        razones: this.topUserReasons([...critical, ...suspicious], 5),
      };
    }

    if (suspicious.length > 0 || capabilities.length >= 3) {
      return {
        nivel: 'medio',
        veredicto: 'sospechosa',
        resumen:
          'La extensión tiene capacidades sensibles o señales que deben justificarse por su propósito.',
        razones: this.topUserReasons([...suspicious, ...capabilities], 4),
      };
    }

    if (capabilities.length > 0) {
      return {
        nivel: 'medio',
        veredicto: 'benigna',
        resumen:
          'No vimos abuso confirmado, pero la extensión sí declara algunas capacidades que conviene entender.',
        razones: this.topUserReasons(capabilities, 3),
      };
    }

    return {
      nivel: 'bajo',
      veredicto: 'benigna',
      resumen:
        'No vimos señales relevantes de abuso en las categorías principales evaluadas.',
      razones: [
        'No se detectaron capacidades críticas ni comportamiento sospechoso.',
      ],
    };
  }

  /**
   * Extracts every chrome.* call site from the preprocessed files and maps
   * each one to its declared permission root (e.g. `chrome.tabs.query` →
   * `tabs`). Used by the evaluators to detect actual usage of declared
   * permissions, not just their presence in the manifest.
   *
   * Library files are skipped — a polyfill or analytics SDK calling
   * `chrome.runtime.id` isn't the extension's own behavior.
   */
  private collectApiCalls(
    preprocessed: PreprocessorOutput,
  ): ChromeApiCallSite[] {
    const out: ChromeApiCallSite[] = [];
    for (const file of preprocessed.files) {
      if (file.role === 'library') continue;
      for (const api of file.chromeApis ?? []) {
        const root = api.api.replace(/^chrome\./, '').split('.')[0];
        if (!root) continue;
        out.push({
          api: api.api,
          permission: root,
          filePath: file.path,
          fileRole: file.role,
          line: api.line,
        });
      }
    }
    return out;
  }

  private collectCategoryEvidence(
    preprocessed: PreprocessorOutput,
    staticFindings: VerdictedStaticFinding[],
    domainFindings: VerdictedDomainFinding[],
    dynamicFindings: DynamicVerdictedFinding[],
  ): Map<UserRiskSummaryId, string[]> {
    const grouped = new Map<UserRiskSummaryId, string[]>();
    const add = (id: UserRiskSummaryId, text: string) => {
      const list = grouped.get(id) ?? [];
      list.push(text);
      grouped.set(id, list);
    };

    this.collectManifestEvidence(preprocessed, add);
    this.collectStaticEvidence(staticFindings, add);
    this.collectDomainEvidence(domainFindings, add);
    this.collectDynamicEvidence(dynamicFindings, add);

    for (const [key, values] of grouped) {
      grouped.set(key, uniqueStrings(values).slice(0, 5));
    }
    return grouped;
  }

  private collectManifestEvidence(
    preprocessed: PreprocessorOutput,
    add: (id: UserRiskSummaryId, text: string) => void,
  ): void {
    const perms = new Set([
      ...preprocessed.manifest.apiPermissions,
      ...preprocessed.manifest.optionalPermissions,
    ]);
    const hostPerms = preprocessed.manifest.hostPermissions ?? [];
    const contentMatches = preprocessed.manifest.contentScripts.flatMap(
      (cs) => cs.matches,
    );

    if ([...hostPerms, ...contentMatches].some((p) => this.isBroadHostPattern(p))) {
      add(
        'acceso_general_navegador',
        'Puede operar en muchos o todos los sitios web por permisos de host.',
      );
    }
    if (preprocessed.manifest.contentScripts.length > 0) {
      add(
        'acceso_general_navegador',
        'Tiene content scripts que pueden ejecutarse automáticamente al visitar páginas.',
      );
      add(
        'lectura_informacion',
        'Los content scripts pueden leer o inspeccionar el DOM de las páginas donde corren.',
      );
    }
    if (perms.has('scripting')) {
      add(
        'modificacion_paginas',
        'Permiso scripting permite inyectar código en páginas.',
      );
    }
    if (perms.has('tabs')) {
      add('acceso_historial', 'Puede ver URL y título de pestañas abiertas.');
      add(
        'seguimiento_privacidad',
        'Puede observar navegación activa mediante pestañas.',
      );
    }
    if (perms.has('history')) {
      add(
        'acceso_historial',
        'Permiso history permite leer historial de navegación.',
      );
    }
    if (perms.has('cookies')) {
      add(
        'captura_credenciales',
        'Permiso cookies puede exponer sesiones activas.',
      );
    }
    if (perms.has('downloads')) {
      add('descargas_archivos', 'Permiso downloads permite gestionar descargas.');
    }
    if (perms.has('webRequest') || perms.has('declarativeNetRequest')) {
      add(
        'manipulacion_trafico',
        'Puede observar, bloquear o redirigir solicitudes web según reglas/permisos.',
      );
    }
    if (perms.has('webRequestBlocking') || perms.has('proxy')) {
      add(
        'manipulacion_trafico',
        'Tiene permisos de alto impacto para bloquear, redirigir o modificar tráfico.',
      );
    }
  }

  private collectStaticEvidence(
    findings: VerdictedStaticFinding[],
    add: (id: UserRiskSummaryId, text: string) => void,
  ): void {
    for (const finding of findings) {
      for (const rule of USER_RISK_STATIC_RULES) {
        if (rule.matches(finding)) add(rule.id, rule.evidence(finding));
      }
    }
  }

  private collectTriggeredRules(
    findings: VerdictedStaticFinding[],
  ): Map<UserRiskSummaryId, string[]> {
    const grouped = new Map<UserRiskSummaryId, string[]>();
    const add = (id: UserRiskSummaryId, ruleId: string) => {
      const list = grouped.get(id) ?? [];
      list.push(ruleId);
      grouped.set(id, list);
    };
    for (const finding of findings) {
      for (const rule of USER_RISK_STATIC_RULES) {
        if (rule.matches(finding)) add(rule.id, rule.ruleId);
      }
    }
    for (const [key, values] of grouped) {
      grouped.set(key, uniqueStrings(values));
    }
    return grouped;
  }

  private collectDomainEvidence(
    domainFindings: VerdictedDomainFinding[],
    add: (id: UserRiskSummaryId, text: string) => void,
  ): void {
    for (const domain of domainFindings) {
      if (
        domain.veredicto !== 'positivo' ||
        domain.discoveryType !== 'url_en_codigo'
      )
        continue;
      add(
        'seguimiento_privacidad',
        `Contacta ${domain.domain} (${domain.category}).`,
      );
    }
  }

  private collectDynamicEvidence(
    dynamicFindings: DynamicVerdictedFinding[],
    add: (id: UserRiskSummaryId, text: string) => void,
  ): void {
    for (const dynamic of dynamicFindings) {
      const text = `Análisis dinámico: ${dynamic.razon}`;
      add('seguimiento_privacidad', text);
      if (/cookie|session|sesión|password|contraseña|token|credential/i.test(text)) {
        add('captura_credenciales', text);
      }
      if (/tecla|keyboard|keylog|input/i.test(text)) {
        add('keylogging', text);
      }
      if (/redirect|redirig|request|tráfico|traffic/i.test(text)) {
        add('manipulacion_trafico', text);
      }
    }
  }

  private topUserReasons(
    items: UserRiskSummaryItem[],
    limit: number,
  ): string[] {
    const ordered = [...items].sort(
      (a, b) => this.userStatusWeight(b.estado) - this.userStatusWeight(a.estado),
    );
    return ordered
      .flatMap((item) => {
        const evidence = item.evidencias[0];
        return evidence
          ? `${item.titulo}: ${item.resumen} Evidencia: ${evidence}`
          : `${item.titulo}: ${item.resumen}`;
      })
      .slice(0, limit);
  }

  private userStatusWeight(status: UserRiskStatus): number {
    switch (status) {
      case 'critico':
        return 4;
      case 'sospechoso':
        return 3;
      case 'capacidad':
        return 2;
      default:
        return 1;
    }
  }

  private isBroadHostPattern(pattern: string): boolean {
    return (
      pattern === '<all_urls>' ||
      pattern === '*://*/*' ||
      pattern === 'http://*/*' ||
      pattern === 'https://*/*'
    );
  }
}
