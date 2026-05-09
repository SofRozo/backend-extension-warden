import { Test, TestingModule } from '@nestjs/testing';
import { ReportService } from '../report.service.js';
import { StructuredLogger } from '../../common/logger/logger.service.js';
import type {
  AgentAnalysisResult,
  VerdictedStaticFinding,
  VerdictedDomainFinding,
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

  const baseStatic: VerdictedStaticFinding = {
    fileType: 'content_script',
    filePath: 'src/main.js',
    discoveryType: 'listener_teclado',
    detail: 'keydown',
    line: 42,
    veredicto: 'positivo',
    razon: 'keylogger en content_script sin justificación',
  };

  const basePriority: VerdictedDomainFinding = {
    fileType: 'background',
    filePath: 'src/bg.js',
    discoveryType: 'url_en_codigo',
    domain: 'instagram.com',
    category: 'sensible_redes_sociales',
    priority: 5,
    line: 10,
    veredicto: 'positivo',
    razon: 'extensión de mascota no debería contactar redes sociales',
  };

  const baseDynamic: DynamicVerdictedFinding = {
    fileType: 'background',
    filePath: 'src/bg.js',
    discoveryType: 'url_en_codigo',
    domain: 'instagram.com',
    category: 'sensible_redes_sociales',
    priority: 5,
    line: 10,
    veredicto: 'maliciosa',
    accion_hecha: 'envió cookies de sesión a un dominio externo',
    razon: 'la extensión exfiltró cookies durante la navegación',
  };

  const buildAgents = (): AgentAnalysisResult => ({
    agent1: {
      proposito: 'Mascota virtual',
      categoria: 'entretenimiento',
      acciones_esperadas: ['mostrar mascota'],
      acciones_NO_esperadas: ['acceder a redes sociales'],
      senales_alarma_manifest: [],
      nivel_riesgo_inicial: 'medio',
      razon_nivel_riesgo: 'permisos amplios',
    },
    agent2: [baseStatic],
    agent3: { priority: [basePriority], unknown: [] },
    agent4: [baseDynamic],
    ranSuccessfully: true,
    errors: [],
  });

  it('returns the new minimal report shape', () => {
    const report = service.generateReport(
      'job-1',
      'ext-1',
      1234,
      { name: 'Test Ext', version: '1.0', author: 'tester', crxHash: 'abc' },
      buildAgents(),
    );

    expect(report.agente1?.proposito).toBe('Mascota virtual');
    expect(report.dominios_contactados_prioritarios).toEqual([
      'https://instagram.com',
    ]);
    expect(report.hallazgos_estaticos_positivos.length).toBe(2);
    expect(report.hallazgos_estaticos_positivos[0]).toContain('content script');
    expect(report.hallazgos_estaticos_positivos[0]).toContain('src/main.js');
    expect(report.hallazgos_estaticos_positivos[0]).toContain('línea 42');
    expect(report.hallazgos_dinamicos_positivos.length).toBe(1);
    expect(report.hallazgos_dinamicos_positivos[0]).toContain('por tanto');
    expect(report.estructura.resultado1).toEqual([baseStatic]);
    expect(report.estructura.resultado2_priority).toEqual([basePriority]);
    expect(report.estructura.resultado_dinamico).toEqual([baseDynamic]);
  });

  it('filters out findings with falso_positivo verdict', () => {
    const agent: AgentAnalysisResult = {
      ...buildAgents(),
      agent2: [{ ...baseStatic, veredicto: 'falso_positivo' }],
      agent3: {
        priority: [{ ...basePriority, veredicto: 'falso_positivo' }],
        unknown: [],
      },
      agent4: [{ ...baseDynamic, veredicto: 'benigna' }],
    };

    const report = service.generateReport(
      'job-2',
      'ext-2',
      0,
      { crxHash: 'h' },
      agent,
    );

    expect(report.hallazgos_estaticos_positivos).toHaveLength(0);
    expect(report.hallazgos_dinamicos_positivos).toHaveLength(0);
  });

  it('handles missing agents gracefully', () => {
    const report = service.generateReport(
      'job-3',
      'ext-3',
      0,
      { crxHash: 'h' },
      {
        agent1: null,
        agent2: null,
        agent3: null,
        agent4: null,
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
