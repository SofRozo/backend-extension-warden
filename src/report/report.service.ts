import { Injectable } from '@nestjs/common';
import { StructuredLogger } from '../common/logger/logger.service.js';
import {
  AnalysisReport,
  AgentAnalysisResult,
  VerdictedStaticFinding,
  VerdictedDomainFinding,
  DynamicVerdictedFinding,
  DomainNavigationLog,
  SandboxDomainObservation,
} from '../common/interfaces/analysis.interfaces.js';

const FILE_TYPE_LABEL: Record<string, string> = {
  content_script: 'content script',
  background: 'background',
  popup: 'popup',
  library: 'librería',
  unknown: 'archivo',
  manifest: 'manifest',
};

@Injectable()
export class ReportService {
  constructor(private readonly logger: StructuredLogger) {}

  generateReport(
    jobId: string,
    extensionId: string,
    analysisDuration: number,
    metadata: { name?: string; version?: string; author?: string; crxHash: string },
    agentAnalysis: AgentAnalysisResult,
    domainObservations: SandboxDomainObservation[] = [],
  ): AnalysisReport {
    const resultado1 = agentAnalysis.agent2 ?? [];
    const priority = agentAnalysis.agent3?.priority ?? [];
    const unknown = agentAnalysis.agent3?.unknown ?? [];
    const dinamico = agentAnalysis.agent4 ?? [];

    const navegacionDominios: DomainNavigationLog[] = domainObservations.map(
      (o) => ({
        domain: o.domain,
        url: o.url,
        navigatorUsed: o.navigatorUsed,
        honeypotSessionUsed: o.honeypotSessionUsed,
        agentSteps: o.agentSteps,
        actionsPerformed: o.actionsPerformed,
        error: o.error,
      }),
    );

    const dominios = this.uniqueDomainsFromPriority(priority);
    const hallazgosEstaticos = resultado1
      .filter((f) => f.veredicto === 'positivo')
      .map((f) => this.formatStatic(f));
    const hallazgosDomain = [...priority, ...unknown]
      .filter((f) => f.veredicto === 'positivo')
      .map((f) => this.formatStaticDomain(f));
    const hallazgosDinamicos = dinamico
      .filter(
        (f) => f.veredicto === 'maliciosa' || f.veredicto === 'sospechosa',
      )
      .map((f) => this.formatDynamic(f));

    this.logger.logWithJob(
      jobId,
      'info',
      `Report generated: ${hallazgosEstaticos.length} static, ` +
        `${hallazgosDomain.length} domain-static, ${hallazgosDinamicos.length} dynamic findings`,
      'ReportService',
    );

    return {
      jobId,
      extensionId,
      extensionName: metadata.name,
      extensionVersion: metadata.version,
      extensionAuthor: metadata.author,
      crxHash: metadata.crxHash,
      analysisTimestamp: new Date(),
      analysisDuration,
      agente1: agentAnalysis.agent1,
      dominios_contactados_prioritarios: dominios,
      hallazgos_estaticos_positivos: [...hallazgosEstaticos, ...hallazgosDomain],
      hallazgos_dinamicos_positivos: hallazgosDinamicos,
      estructura: {
        resultado1,
        resultado2_priority: priority,
        resultado2_unknown: unknown,
        resultado_dinamico: dinamico,
      },
      navegacionDominios,
    };
  }

  // ─── Formatters ────────────────────────────────────────────────────────────

  private formatStatic(f: VerdictedStaticFinding): string {
    const fileType = FILE_TYPE_LABEL[f.fileType] ?? f.fileType;
    return (
      `En el ${fileType} de la extensión, en la ruta ${f.filePath}, línea ${f.line}, ` +
      `descubrimos que ${f.discoveryType} (${f.detail}), porque ${f.razon}`
    );
  }

  private formatStaticDomain(f: VerdictedDomainFinding): string {
    const fileType = FILE_TYPE_LABEL[f.fileType] ?? f.fileType;
    const detail = `${f.domain} clasificado como ${f.category}`;
    return (
      `En el ${fileType} de la extensión, en la ruta ${f.filePath}, línea ${f.line}, ` +
      `descubrimos que ${f.discoveryType} (${detail}), porque ${f.razon}`
    );
  }

  private formatDynamic(f: DynamicVerdictedFinding): string {
    const fileType = FILE_TYPE_LABEL[f.fileType] ?? f.fileType;
    const detail = `${f.domain} clasificado como ${f.category}`;
    return (
      `En el ${fileType} de la extensión, en la ruta ${f.filePath}, línea ${f.line}, ` +
      `descubrimos que ${f.discoveryType} (${detail}), porque ${f.accion_hecha}, por tanto ${f.razon}`
    );
  }

  private uniqueDomainsFromPriority(
    priority: VerdictedDomainFinding[],
  ): string[] {
    const set = new Set<string>();
    for (const f of priority) {
      set.add(`https://${f.domain}`);
    }
    return [...set];
  }
}
