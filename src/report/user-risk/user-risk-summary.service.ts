import { Injectable } from '@nestjs/common';
import type {
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
  ): UserRiskSummaryItem[] {
    const positives = staticFindings.filter((f) => f.veredicto === 'positivo');
    const perms = new Set([
      ...preprocessed.manifest.apiPermissions,
      ...preprocessed.manifest.optionalPermissions,
    ]);
    const contentMatches = preprocessed.manifest.contentScripts.flatMap(
      (cs) => cs.matches,
    );

    // Build a set of filePath:line keys that VerdictService explicitly marked
    // as falso_positivo. Any API call site at those coordinates is excluded
    // from apiCalls so it cannot escalate categories to sospechoso/critico.
    const falsoPosKeys = new Set<string>(
      staticFindings
        .filter((f) => f.veredicto === 'falso_positivo')
        .map((f) => `${f.filePath}:${f.line}`),
    );

    const apiCalls = this.collectApiCalls(preprocessed, falsoPosKeys);
    const usedPermissions = new Set<string>();
    for (const call of apiCalls) usedPermissions.add(call.permission);
    // unusedPermissions = declared but never invoked. This is the signal that
    // surfaces overprivileged extensions ("pide X pero no lo usa") which the
    // user-risk evaluators previously couldn't see.
    const unusedPermissions = new Set<string>();
    for (const p of perms) {
      if (!usedPermissions.has(p)) unusedPermissions.add(p);
    }

    // broadHost is only true when a broad host-permission finding survived
    // VerdictService (i.e. was NOT marked falso_positivo). Reading the raw
    // manifest directly ignores verdicts and causes false escalations in benign
    // extensions where a wide host pattern was justified / dismissed.
    const broadHostPatternPositive = positives.some(
      (f) =>
        f.discoveryType === 'permiso_chrome_manifest_riesgoso' &&
        /(<all_urls>|\*:\/\/\*\/\*|http:\/\/\*\/\*|https:\/\/\*\/\*)/.test(
          f.detail,
        ),
    );
    // Content-script matches are not individually verdicted, so fall back to
    // the raw list for those — but only when the broad pattern itself wasn't
    // dismissed at the manifest-permission level.
    const broadHostContentScript = contentMatches.some((p) =>
      this.isBroadHostPattern(p),
    );

    const context: UserRiskContext = {
      preprocessed,
      positives,
      domainFindings,
      perms,
      broadHost: broadHostPatternPositive || broadHostContentScript,
      hasContentScript: preprocessed.manifest.contentScripts.length > 0,
      apiCalls,
      usedPermissions,
      unusedPermissions,
      evidenceByCategory: this.collectCategoryEvidence(
        preprocessed,
        positives,
        domainFindings,
      ),
      triggeredRulesByCategory: this.collectTriggeredRules(positives),
      cwsCategory: preprocessed.cwsCategory ?? null,
    };

    const summary = USER_RISK_CATEGORY_EVALUATORS.map((evaluate) =>
      evaluate(context),
    );

    return this.orderSummary(summary);
  }

  /**
   * Derives the 10 FAQ answers deterministically from category states.
   * Used as fallback when Agent 1 fails or is disabled.
   */
  buildFallbackRespuestas(
    summary: UserRiskSummaryItem[],
  ): Record<string, 'si' | 'posible' | 'no_detectado'> {
    const state = (id: UserRiskSummaryId): UserRiskStatus =>
      summary.find((i) => i.id === id)?.estado ?? 'no_detectado';

    const map = (status: UserRiskStatus): 'si' | 'posible' | 'no_detectado' => {
      if (status === 'critico') return 'si';
      if (status === 'sospechoso') return 'posible';
      if (status === 'capacidad') return 'posible';
      return 'no_detectado';
    };

    const creds = state('captura_credenciales');
    const keylog = state('keylogging');
    const lectura = state('lectura_informacion');
    const mod = state('modificacion_paginas');
    const trafico = state('manipulacion_trafico');
    const historial = state('acceso_historial');
    const general = state('acceso_general_navegador');
    const ofusc = state('ofuscacion_transparencia');
    const mgmt = state('abuso_management');

    return {
      puede_capturar_contrasenas: map(creds),
      puede_registrar_teclas: map(keylog),
      puede_espiar_sin_saberlo:
        creds === 'critico' || keylog === 'critico' || lectura === 'critico'
          ? 'si'
          : creds === 'sospechoso' ||
              keylog === 'sospechoso' ||
              lectura === 'sospechoso'
            ? 'posible'
            : 'no_detectado',
      puede_leer_formularios: map(lectura),
      puede_modificar_paginas: map(mod),
      puede_interceptar_trafico: map(trafico),
      puede_ver_paginas_visitadas: map(general),
      puede_ver_historial: map(historial),
      codigo_oculto_o_sospechoso: map(ofusc),
      puede_afectar_otras_extensiones: map(mgmt),
    };
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
      criticalIds.has('abuso_management') ||
      criticalIds.has('mineria_recursos') ||
      criticalIds.has('fingerprinting_severo') ||
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
    falsoPosKeys: Set<string>,
  ): ChromeApiCallSite[] {
    const out: ChromeApiCallSite[] = [];
    for (const file of preprocessed.files) {
      if (file.role === 'library') continue;
      for (const api of file.chromeApis ?? []) {
        const root = api.api.replace(/^chrome\./, '').split('.')[0];
        if (!root) continue;
        // Skip API call sites that VerdictService explicitly dismissed.
        if (falsoPosKeys.has(`${file.path}:${api.line}`)) continue;
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

    if (
      [...hostPerms, ...contentMatches].some((p) => this.isBroadHostPattern(p))
    ) {
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
      add(
        'descargas_archivos',
        'Permiso downloads permite gestionar descargas.',
      );
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
      if (domain.veredicto !== 'positivo') continue;

      if (domain.discoveryType === 'url_en_codigo') {
        add(
          'seguimiento_privacidad',
          `Contacta ${domain.domain} (${domain.category}).`,
        );
        // Sensitive domain categories surfaced in code also elevate general access
        if (/financiero|identidad|llm|correo|redes|gob/.test(domain.category)) {
          add(
            'acceso_general_navegador',
            `Código referencia dominio sensible: ${domain.domain} (${domain.category}).`,
          );
        }
      }

      if (domain.discoveryType === 'host_permission_manifest') {
        // Broad host_permissions declared in manifest give unrestricted reach
        add(
          'acceso_general_navegador',
          `Declara host_permission para ${domain.domain} — puede actuar en ese sitio automáticamente.`,
        );
        if (/financiero|identidad|llm|correo|redes|gob/.test(domain.category)) {
          add(
            'captura_credenciales',
            `Tiene host_permission declarada para sitio sensible: ${domain.domain} (${domain.category}).`,
          );
          add(
            'acceso_historial',
            `Host permission para sitio sensible puede implicar lectura de URLs en ${domain.domain}.`,
          );
        }
      }
    }
  }

  private topUserReasons(
    items: UserRiskSummaryItem[],
    limit: number,
  ): string[] {
    const ordered = [...items].sort(
      (a, b) =>
        this.userStatusWeight(b.estado) - this.userStatusWeight(a.estado),
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

  private orderSummary(items: UserRiskSummaryItem[]): UserRiskSummaryItem[] {
    const categoryPriority: Record<UserRiskSummaryId, number> = {
      captura_credenciales: 100,
      keylogging: 95,
      lectura_informacion: 90,
      manipulacion_trafico: 85,
      modificacion_paginas: 80,
      seguimiento_privacidad: 75,
      abuso_management: 72,
      fingerprinting_severo: 70,
      acceso_general_navegador: 65,
      mineria_recursos: 60,
      acceso_historial: 55,
      descargas_archivos: 45,
      ofuscacion_transparencia: 35,
    };

    return [...items].sort((a, b) => {
      const statusDelta =
        this.userStatusWeight(b.estado) - this.userStatusWeight(a.estado);
      if (statusDelta !== 0) return statusDelta;
      return (categoryPriority[b.id] ?? 0) - (categoryPriority[a.id] ?? 0);
    });
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
