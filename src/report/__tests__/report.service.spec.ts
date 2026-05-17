import { Test, TestingModule } from '@nestjs/testing';
import { ReportService } from '../report.service.js';
import { UserRiskSummaryService } from '../user-risk/user-risk-summary.service.js';
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
        UserRiskSummaryService,
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
      nivel_riesgo_inicial: 'alto',
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
    expect(report.resumen_usuario).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          id: 'keylogging',
          titulo: 'Keylogging y captura de teclado',
        }),
        expect.objectContaining({
          id: 'captura_credenciales',
          titulo: 'Contraseñas, tokens y sesiones',
        }),
      ]),
    );
    expect(report.veredicto_usuario).toEqual(
      expect.objectContaining({
        nivel: expect.any(String),
        veredicto: expect.any(String),
        resumen: expect.any(String),
      }),
    );
    expect(report.veredicto_usuario.razones.length).toBeGreaterThan(0);
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

  it('explains obfuscation in user-friendly terms', () => {
    const obfuscated: PreprocessingFinding = {
      fileType: 'content_script',
      filePath: 'dist/main.js',
      discoveryType: 'codigo_ofuscado',
      detail: 'archivo ofuscado o agresivamente minificado',
      line: 1,
      severity: 'high',
      confidence: 0.82,
      why: 'The code contains obfuscation or aggressive minification signals that reduce auditability.',
    };

    const report = service.generateReport(
      'job-4',
      'ext-4',
      0,
      { crxHash: 'h' },
      buildPreprocessed({ resultado1: [obfuscated], resultado2_priority: [] }),
      buildAgents({ agent2: [] }),
    );

    expect(report.hallazgos_estaticos_positivos[0]).toContain(
      'no prueba malware por sí solo',
    );
    expect(report.hallazgos_estaticos_positivos[0]).toContain(
      'Minificar nombres para reducir tamaño es normal',
    );
    expect(report.hallazgos_estaticos_positivos[0]).toContain(
      'reduce la transparencia',
    );
  });

  it('groups repetitive static findings in the user-facing narrative', () => {
    const repeatedCookies: PreprocessingFinding[] = Array.from(
      { length: 30 },
      (_, index) => ({
        fileType: 'content_script',
        filePath: `ruleset-${index}.js`,
        discoveryType: 'lectura_cookies',
        detail: 'document.cookie',
        line: index + 1,
        severity: 'high',
        confidence: 0.85,
        why: 'Cookie access can expose session identifiers.',
      }),
    );

    const report = service.generateReport(
      'job-group',
      'ext-group',
      0,
      { crxHash: 'h' },
      buildPreprocessed({
        resultado1: repeatedCookies,
        resultado2_priority: [],
      }),
      buildAgents({ agent2: [] }),
    );

    expect(report.hallazgos_estaticos_positivos).toHaveLength(1);
    expect(report.hallazgos_estaticos_positivos[0]).toContain(
      '29 ocurrencia(s) similar(es)',
    );
  });

  it('does not report manifest host permissions as contacted domains', () => {
    const hostOnly: DomainFinding = {
      ...basePriority,
      fileType: 'manifest',
      filePath: 'manifest.json',
      discoveryType: 'host_permission_manifest',
      domain: 'instagram.com',
      line: 4,
    };

    const report = service.generateReport(
      'job-host',
      'ext-host',
      0,
      { crxHash: 'h' },
      buildPreprocessed({ resultado2_priority: [hostOnly] }),
      buildAgents({ agent2: [] }),
    );

    expect(report.dominios_contactados_prioritarios).toEqual([]);
    expect(report.hallazgos_estaticos_positivos[1]).toContain(
      'declarado como permiso de host',
    );
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
