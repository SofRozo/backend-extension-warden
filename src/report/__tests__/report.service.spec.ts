import { Test, TestingModule } from '@nestjs/testing';
import { ReportService } from '../report.service.js';
import { StructuredLogger } from '../../common/logger/logger.service.js';
import type {
  AgentAnalysisResult,
  PreprocessorOutput,
  PreprocessingFinding,
  DomainFinding,
  DynamicVerdictedFinding,
} from '../../common/interfaces/analysis.interfaces.js';

describe('ReportService', () => {
  let service: ReportService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        ReportService,
        { provide: StructuredLogger, useValue: { logWithJob: jest.fn() } },
      ],
    }).compile();

    service = module.get<ReportService>(ReportService);
  });

  const baseStatic: PreprocessingFinding = {
    fileType: 'content_script',
    filePath: 'src/main.js',
    discoveryType: 'listener_teclado',
    detail: 'keydown',
    line: 42,
    severity: 'critical',
    confidence: 0.95,
    why: 'keylogger en content_script con sink de red en el mismo archivo',
  };

  const basePriority: DomainFinding = {
    fileType: 'background',
    filePath: 'src/bg.js',
    discoveryType: 'url_en_codigo',
    domain: 'instagram.com',
    category: 'sensible_redes_sociales',
    priority: 6,
    line: 10,
  };

  const baseDynamic: DynamicVerdictedFinding = {
    fileType: 'background',
    filePath: 'src/bg.js',
    discoveryType: 'url_en_codigo',
    domain: 'instagram.com',
    category: 'sensible_redes_sociales',
    priority: 6,
    line: 10,
    veredicto: 'maliciosa',
    accion_hecha: 'envió cookies de sesión a un dominio externo',
    razon: 'la extensión exfiltró cookies durante la navegación',
  };

  const buildPreprocessed = (
    overrides: Partial<PreprocessorOutput> = {},
  ): PreprocessorOutput => ({
    crxHash: 'abc',
    extractPath: '/tmp/ext',
    manifest: {
      manifestVersion: 3,
      name: 'Test Ext',
      version: '1.0',
      apiPermissions: [],
      hostPermissions: [],
      optionalPermissions: [],
      contentScripts: [],
      backgroundScripts: [],
      sandboxPages: [],
      chromeUrlOverrides: {},
      webAccessibleResources: [],
      declarativeNetRequestRules: [],
      permissionRisk: [],
      rawManifest: {},
    },
    files: [],
    resources: [],
    nestedArchives: [],
    dependencyGraph: {
      entries: [],
      edges: [],
      reachable: [],
      orphanScripts: [],
      unresolved: [],
    },
    obfuscatedFileCount: 0,
    hasObfuscation: false,
    remoteCodeViolations: [],
    resultado1: [baseStatic],
    resultado2_priority: [basePriority],
    resultado2_unknown: [],
    ...overrides,
  });

  const buildAgents = (
    overrides: Partial<AgentAnalysisResult> = {},
  ): AgentAnalysisResult => ({
    agent1: {
      proposito: 'Mascota virtual',
      categoria: 'entretenimiento',
      acciones_esperadas: ['mostrar mascota'],
      acciones_NO_esperadas: ['acceder a redes sociales'],
      senales_alarma_manifest: [],
      nivel_riesgo_inicial: 'alto',
      razon_nivel_riesgo: 'permisos amplios y exfiltración detectada',
      veredicto_global: 'maliciosa',
      explicacion:
        'La extensión declara ser una mascota virtual pero registra teclas y contacta Instagram, lo que no es coherente con su propósito declarado.',
    },
    agent2: [baseDynamic],
    ranSuccessfully: true,
    errors: [],
    ...overrides,
  });

  it('builds a full report with deterministic narratives when agent1 omits them', () => {
    const report = service.generateReport(
      'job-1',
      'ext-1',
      1234,
      { name: 'Test Ext', version: '1.0', author: 'tester', crxHash: 'abc' },
      buildPreprocessed(),
      buildAgents(),
    );

    expect(report.agente1?.veredicto_global).toBe('maliciosa');
    expect(report.dominios_contactados_prioritarios).toEqual([
      'https://instagram.com',
    ]);
    expect(report.hallazgos_estaticos_positivos.length).toBe(2);
    expect(report.hallazgos_estaticos_positivos[0]).toContain('content script');
    expect(report.hallazgos_estaticos_positivos[0]).toContain('src/main.js');
    expect(report.hallazgos_estaticos_positivos[0]).toContain('línea 42');
    expect(report.hallazgos_dinamicos_positivos.length).toBe(1);
    expect(report.hallazgos_dinamicos_positivos[0]).toContain('por tanto');
    expect(report.estructura.resultado1[0].veredicto).toBe('positivo');
    expect(report.estructura.resultado2_priority[0].veredicto).toBe('positivo');
    expect(report.estructura.resultado_dinamico).toEqual([baseDynamic]);
  });

  it('builds static narratives deterministically, independent of any agent output', () => {
    // Even with an Agent 1 that returns a verdict, the per-finding narratives
    // must come from the static-analysis formatter — not from the agent.
    const report = service.generateReport(
      'job-2',
      'ext-2',
      0,
      { crxHash: 'h' },
      buildPreprocessed(),
      buildAgents(),
    );

    expect(report.hallazgos_estaticos_positivos[0]).toContain('content script');
    expect(report.hallazgos_estaticos_positivos[0]).toContain('src/main.js');
    expect(report.hallazgos_estaticos_positivos[0]).toContain('línea 42');
    // The agent's holistic explanation still lands in `agente1.explicacion`,
    // separately from the deterministic per-finding narratives.
    expect(report.agente1?.explicacion).toContain('mascota virtual');
  });

  it('downgrades low-confidence findings to falso_positivo and excludes them from narrative', () => {
    const weak: PreprocessingFinding = {
      ...baseStatic,
      confidence: 0.4,
      severity: 'low',
    };
    const report = service.generateReport(
      'job-3',
      'ext-3',
      0,
      { crxHash: 'h' },
      buildPreprocessed({ resultado1: [weak], resultado2_priority: [] }),
      buildAgents({ agent2: [] }),
    );

    expect(report.estructura.resultado1[0].veredicto).toBe('falso_positivo');
    expect(report.hallazgos_estaticos_positivos).toHaveLength(0);
    expect(report.hallazgos_dinamicos_positivos).toHaveLength(0);
  });

  it('handles missing agents gracefully', () => {
    const report = service.generateReport(
      'job-4',
      'ext-4',
      0,
      { crxHash: 'h' },
      buildPreprocessed({
        resultado1: [],
        resultado2_priority: [],
      }),
      {
        agent1: null,
        agent2: null,
        ranSuccessfully: false,
        errors: ['no LLM'],
      },
    );

    expect(report.agente1).toBeNull();
    expect(report.dominios_contactados_prioritarios).toEqual([]);
    expect(report.hallazgos_estaticos_positivos).toEqual([]);
    expect(report.hallazgos_dinamicos_positivos).toEqual([]);
  });
});
