import { Injectable } from '@nestjs/common';
import { LlmClientService } from '../llm/llm-client.service.js';
import { DomainClassifierService } from './domain-classifier.service.js';
import { StructuredLogger } from '../../common/logger/logger.service.js';
import type { PreprocessorOutput, ProcessedFile } from '../../common/interfaces/analysis.interfaces.js';
import type {
  Agent1Output,
  Agent2Output,
  Agent2Finding,
  CategorizedDomain,
  DomainCategory,
} from '../interfaces/agents.interfaces.js';
import { ThreatIntelService } from '../../threat-intel/threat-intel.service.js';

// ─── Prompt ───────────────────────────────────────────────────────────────────

const PROMPT = `Eres un experto en seguridad de extensiones de navegador realizando análisis estático.

PROPÓSITO DE LA EXTENSIÓN (Agente 1):
{contexto_agente1}

ARCHIVOS A ANALIZAR:
{archivos}

DATOS DE THREAT INTEL PARA DOMINIOS SIN CLASIFICAR (VirusTotal, puede estar vacío):
{enriquecimiento_dominios}

DOMINIOS QUE REQUIEREN TU CLASIFICACIÓN (los obvios ya fueron clasificados):
{dominios_sin_clasificar}

Tu tarea tiene dos partes:

PARTE 1 — ANÁLISIS DE CÓDIGO
Para cada archivo (content_script, background, unknown):
- ¿Qué datos del DOM o del usuario lee o modifica?
- ¿Hacia qué dominios hace peticiones y con qué datos?
- ¿Hay flujos lectura→red? (ej: lee innerHTML de un campo → lo envía con fetch)
- ¿Usa APIs de Chrome sensibles y en qué contexto?
- Nota: un keydown listener en POPUP es normal (UX del popup). En content_script es un keylogger potencial.

PARTE 2 — CLASIFICACIÓN DE DOMINIOS
Para los dominios sin clasificar, razona sobre cada uno:
- ¿Parece propio del desarrollador (similar al nombre de la extensión)?
- ¿Pertenece a un sector sensible aunque no use palabras clave obvias?
  (ej: "davivienda.com.co" es un banco colombiano aunque no diga "banco")
- ¿No tiene relación con el propósito declarado? → desconocido

Categorías disponibles para la clasificación:
- propio_extension: servidor del desarrollador
- sensible_financiero: banco, fintech, cripto, pagos, carteras digitales
- sensible_gubernamental: portal de gobierno, impuestos, servicios ciudadanos
- sensible_identidad: proveedor de autenticación u OAuth no listado en los obvios (Google, Microsoft, etc.)
- sensible_correo_productividad: servicio de correo o suite de productividad no listado en los obvios
- desconocido: no puedes clasificar con certeza

Responde en JSON exactamente así (sin texto adicional):
{
  "hallazgos": [
    {
      "archivo": "ruta/archivo.js",
      "rol": "content_script|background|unknown",
      "descripcion": "descripción clara del comportamiento detectado",
      "severidad": "critica|alta|media|baja|info",
      "tipo": "keylogger|exfiltracion|inyeccion|persistencia|datos|otro",
      "evidencia": "fragmento de código o descripción específica"
    }
  ],
  "dominios_clasificados_por_llm": [
    {
      "dominio": "ejemplo.com",
      "categoria": "propio_extension|sensible_financiero|sensible_gubernamental|sensible_identidad|sensible_correo_productividad|desconocido",
      "razonamiento": "explicación de por qué esta categoría"
    }
  ],
  "flujos_datos_sospechosos": ["descripción del flujo lectura→red si existe"],
  "apis_chrome_resumen": "descripción del uso de Chrome APIs en contexto",
  "ofuscacion_observaciones": "observaciones sobre archivos ofuscados si aplica"
}`;

// ─── Code-size limits (to stay within LLM context window) ────────────────────

const MAX_CHARS_PER_FILE = 5_000;
const MAX_TOTAL_CODE_CHARS = 20_000;

// ─── Service ─────────────────────────────────────────────────────────────────

@Injectable()
export class Agent2SastService {
  constructor(
    private readonly llm: LlmClientService,
    private readonly domainClassifier: DomainClassifierService,
    private readonly threatIntel: ThreatIntelService,
    private readonly logger: StructuredLogger,
  ) {}

  async analyze(
    preprocessed: PreprocessorOutput,
    agent1: Agent1Output,
    jobId: string,
  ): Promise<Agent2Output> {
    const { manifest, files } = preprocessed;

    // ── 1. Collect all domains from files + manifest host permissions ─────────
    const allDomains = this.collectAllDomains(files, manifest.hostPermissions);

    // ── 2. First-layer deterministic classification ───────────────────────────
    const alreadyClassified: CategorizedDomain[] = [];
    const needsLLM: string[] = [];

    for (const domain of allDomains) {
      const det = this.domainClassifier.classify(domain, manifest.name, manifest.author);
      if (det.category !== null) {
        const priority = this.domainClassifier.playwrightPriority(det.category);
        alreadyClassified.push(
          this.domainClassifier.buildCategorizedDomain(
            domain,
            det.category,
            det.platform
              ? `Plataforma conocida: ${det.platform}`
              : 'Clasificado por reglas deterministas',
            priority,
          ),
        );
      } else {
        needsLLM.push(domain);
      }
    }

    this.logger.logWithJob(
      jobId,
      'info',
      `Agent 2 — ${alreadyClassified.length} domains classified deterministically, ${needsLLM.length} sent to enrichment + LLM`,
      'Agent2SastService',
    );

    // ── 3. Enrichment Layer (VirusTotal) ──────────────────────────────────────
    let enrichmentData = '';
    if (needsLLM.length > 0) {
      const vtResults = await this.threatIntel.queryDomains(needsLLM, jobId);
      enrichmentData = vtResults
        .map(
          (r) =>
            `- ${r.domain}: [${(r.categories ?? []).join(', ') || 'sin categoría'}]` +
            (r.isMalicious ? ' !! MARCADO COMO MALICIOSO !!' : ''),
        )
        .join('\n');
    }

    // ── 4. Build code sections (truncated, non-popup non-library only) ────────
    const { archivosSection, obfuscatedFiles } = this.buildCodeSection(files);

    // ── 5. Build prompt ───────────────────────────────────────────────────────
    const contextoAgente1 = JSON.stringify(
      {
        proposito: agent1.proposito,
        categoria: agent1.categoria,
        acciones_esperadas: agent1.acciones_esperadas,
        acciones_NO_esperadas: agent1.acciones_NO_esperadas,
        nivel_riesgo_inicial: agent1.nivel_riesgo_inicial,
      },
      null,
      2,
    );

    const dominosSinClasificar =
      needsLLM.length > 0
        ? needsLLM.map((d) => `  - ${d}`).join('\n')
        : '  (ninguno)';

    const prompt = PROMPT
      .replace('{contexto_agente1}', contextoAgente1)
      .replace('{archivos}', archivosSection)
      .replace('{enriquecimiento_dominios}', enrichmentData || '(sin datos)')
      .replace('{dominios_sin_clasificar}', dominosSinClasificar);

    this.logger.logWithJob(jobId, 'info', 'Agent 2 — running SAST + domain classification', 'Agent2SastService');

    const raw = await this.llm.callLLM(prompt, jobId);
    return this.buildOutput(raw, alreadyClassified, obfuscatedFiles, jobId);
  }

  // ─── Helpers ───────────────────────────────────────────────────────────────

  private collectAllDomains(files: ProcessedFile[], hostPermissions: string[]): string[] {
    const domains = new Set<string>();

    for (const f of files) {
      for (const d of f.domains) domains.add(d.domain);
    }

    // Host permissions often contain patterns like "https://*.example.com/*"
    // Extract the bare hostname
    for (const hp of hostPermissions) {
      try {
        const hostname = new URL(hp.replace('*', 'x')).hostname.replace(/^x\./, '');
        if (hostname && hostname !== 'x' && !hostname.includes('*')) {
          domains.add(hostname);
        }
      } catch { /* skip malformed patterns */ }
    }

    return [...domains].filter((d) => d.length > 3);
  }

  private buildCodeSection(
    files: ProcessedFile[],
  ): { archivosSection: string; obfuscatedFiles: string[] } {
    const obfuscatedFiles: string[] = [];
    const sections: string[] = [];
    let totalChars = 0;

    // Priority order: content_script > background > unknown (popup and library excluded)
    const analysisRoles = ['content_script', 'background', 'unknown'] as const;

    // Sort files: high-risk indicators first (usesFetch + usesEval + usesDomManipulation)
    const priority = (f: ProcessedFile) =>
      (f.usesFetch ? 3 : 0) + (f.usesEval ? 2 : 0) + (f.usesDomManipulation ? 1 : 0);

    const filesToAnalyze = files
      .filter((f) => (analysisRoles as readonly string[]).includes(f.role))
      .sort((a, b) => priority(b) - priority(a));

    for (const file of filesToAnalyze) {
      if (file.isObfuscated) {
        obfuscatedFiles.push(file.path);
        sections.push(
          `### ${file.path} [${file.role}] — OFUSCADO\n` +
          `(Sin código legible. La presencia de ofuscación es en sí misma una señal de alerta.)\n` +
          `Domains encontrados: ${file.domains.join(', ') || 'ninguno'}\n` +
          `Chrome APIs: ${file.chromeApis.map((a) => a.api).join(', ') || 'ninguna'}`,
        );
        continue;
      }

      const code = file.cleanCode ?? '';
      const snippet = totalChars < MAX_TOTAL_CODE_CHARS
        ? code.slice(0, MAX_CHARS_PER_FILE)
        : '[OMITIDO — límite de contexto alcanzado]';

      if (snippet !== '[OMITIDO — límite de contexto alcanzado]') {
        totalChars += snippet.length;
      }

      const truncated = code.length > MAX_CHARS_PER_FILE;
      sections.push(
        `### ${file.path} [${file.role}]${truncated ? ' (truncado)' : ''}\n` +
        `Indicadores: fetch=${file.usesFetch}, XHR=${file.usesXHR}, eval=${file.usesEval}, domManip=${file.usesDomManipulation}\n` +
        `Chrome APIs: ${file.chromeApis.map((a) => `${a.api}:L${a.line}`).join(', ') || 'ninguna'}\n` +
        `Domains en código: ${file.domains.map((d) => `${d.domain}:L${d.line}`).join(', ') || 'ninguno'}\n` +
        `\`\`\`js\n${snippet}\n\`\`\``,
      );
    }

    return { archivosSection: sections.join('\n\n'), obfuscatedFiles };
  }

  private buildOutput(
    raw: unknown,
    alreadyClassified: CategorizedDomain[],
    obfuscatedFiles: string[],
    jobId: string,
  ): Agent2Output {
    const r = raw as Record<string, unknown>;
    const llmDomains: CategorizedDomain[] = [];

    // Parse LLM-classified domains — PROMPT returns an array (dominios_clasificados_por_llm)
    if (Array.isArray(r.dominios_clasificados_por_llm)) {
      for (const item of r.dominios_clasificados_por_llm) {
        const d = item as { dominio?: string; categoria?: string; razonamiento?: string };
        if (!d.dominio || !d.categoria) continue;
        const category = d.categoria as DomainCategory;
        const priority = this.domainClassifier.playwrightPriority(category);
        llmDomains.push(
          this.domainClassifier.buildCategorizedDomain(
            d.dominio,
            category,
            d.razonamiento ?? 'Clasificado por LLM',
            priority,
          ),
        );
      }
    }

    const allDomains = [...alreadyClassified, ...llmDomains];

    // Domains that go to Playwright, sorted by priority (lower = sooner)
    const dominosParaPlaywright = allDomains
      .filter((d) => d.goesToPlaywright)
      .sort((a, b) => (a.playwrightPriority ?? 99) - (b.playwrightPriority ?? 99))
      .slice(0, 5); // Plan caps at 5 domains

    // Parse findings — PROMPT key is "hallazgos"
    const hallazgos: Agent2Finding[] = [];
    if (Array.isArray(r.hallazgos)) {
      for (const item of r.hallazgos) {
        const h = item as Partial<Agent2Finding>;
        if (!h.archivo || !h.descripcion) continue;
        hallazgos.push({
          archivo: String(h.archivo),
          rol: h.rol ?? 'unknown',
          descripcion: String(h.descripcion),
          severidad: h.severidad ?? 'media',
          tipo: String(h.tipo ?? 'otro'),
          evidencia: h.evidencia ? String(h.evidencia) : undefined,
        });
      }
    }

    if (!Array.isArray(r.hallazgos)) {
      this.logger.logWithJob(
        jobId,
        'warn',
        'Agent 2 returned no hallazgos array — response may be malformed',
        'Agent2SastService',
      );
    }

    return {
      hallazgos,
      dominios_categorizados: allDomains,
      dominios_para_playwright: dominosParaPlaywright,
      hay_ofuscacion: obfuscatedFiles.length > 0,
      archivos_ofuscados: obfuscatedFiles,
      apis_chrome_resumen: String(r.apis_chrome_resumen ?? ''),
      flujos_datos_sospechosos: Array.isArray(r.flujos_datos_sospechosos)
        ? r.flujos_datos_sospechosos.map(String)
        : [],
    };
  }
}
