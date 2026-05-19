# Pipeline de Análisis

## Flujo completo

```
POST /analyze
  └─ Crea AnalysisJob en PostgreSQL
  └─ Encola en Redis (BullMQ queue "analysis")
  └─ Responde HTTP 202 + jobId

Worker (AnalysisProcessor)
  │
  ├─ [DOWNLOADING]
  │   downloader.downloadAndExtract(extensionId)
  │   └─ Descarga .crx desde CWS (3 métodos con fallback)
  │   └─ Descomprime en /tmp/ext-sandbox/<jobId>/
  │   └─ Calcula SHA-256 del .crx
  │
  ├─ [PREPROCESSING]  ← en paralelo con fetchCwsCategory
  │   preprocessor.preprocess(extractPath)
  │   └─ Lee manifest.json (v2 o v3)
  │   └─ Clasifica archivos por rol (content_script, service_worker, popup…)
  │   └─ Extrae URLs y dominios del código fuente
  │   └─ Detecta archivos obfuscados/minificados
  │   └─ Construye dependency graph
  │   └─ Archivos > 2 MB: regex scan (skippedAst=true), sin AST
  │
  │   staticAnalysis.analyze(preprocessed)
  │   └─ AST parsing con Babel (por archivo)
  │   └─ Taint analysis: flujos datos-sensibles → red
  │   └─ Pattern matching: permisos peligrosos, APIs Chrome, listeners
  │   └─ Deobfuscación: Base64, eval chains
  │   └─ Detección de permisos declarados pero no usados
  │   └─ Correlación de riesgos entre hallazgos
  │
  ├─ [AI_ANALYSIS]
  │   reportService.buildPreAgentSummary(preprocessed)
  │   └─ Evalúa 13 categorías de riesgo (UserRiskSummary)
  │   └─ Genera verdicts sobre hallazgos estáticos
  │
  │   agentsOrchestrator.run(preprocessed, categoriasEvaluadas)
  │   └─ Agent1: envía evidencia al LLM (Ollama qwen3:8b)
  │      ├─ Manifest + permisos + nombre + descripción
  │      ├─ Top 15 hallazgos estáticos (agrupados por tipo, con archivo/línea/fragmento)
  │      ├─ 13 categorías con hallazgos técnicos (archivo, línea, fragmento real)
  │      │   ⚠ Sin etiqueta de estado — el agente razona desde los hechos,
  │      │     no desde una conclusión determinista pre-cocinada
  │      ├─ Código fuente (<3000 chars, archivos más relevantes)
  │      └─ Grep signals de archivos grandes (sin AST)
  │   └─ Salida: veredicto, riesgo, narrativa, 10 respuestas con razón
  │   └─ Si timeout → continúa sin veredicto IA
  │
  ├─ [GENERATING_REPORT]
  │   reportService.generateReport(preprocessed, agent1Output)
  │   └─ Combina hallazgos estáticos + veredicto IA
  │   └─ Construye hallazgos por categoría con evidencias y preguntas
  │   └─ Lista permisos no usados
  │   └─ Calcula score de riesgo (CRITICAL/HIGH/MEDIUM/LOW)
  │   └─ Persiste AnalysisReport en PostgreSQL
  │
  └─ [COMPLETED] o [FAILED]
      downloader.cleanup(extensionId)  ← siempre, incluso en error
```

## Estados del job

| Estado | Descripción |
|--------|-------------|
| `QUEUED` | En cola, esperando worker |
| `DOWNLOADING` | Descargando .crx |
| `PREPROCESSING` | Análisis estático (incluye AST) |
| `AI_ANALYSIS` | Agente LLM procesando |
| `GENERATING_REPORT` | Construyendo reporte final |
| `COMPLETED` | Listo — reporte disponible en `/report/:jobId` |
| `FAILED` | Error — `errorMessage` con detalle |

## Timeouts

| Etapa | Variable | Default |
|-------|----------|---------|
| Todo el job | BullMQ job timeout | `AGENT_TIMEOUT_MS` + margen |
| Agent LLM (Axios) | `AGENT_TIMEOUT_MS` + 90s | 990s |
| Preprocessing | `analysis.preprocessTimeoutMs` | 30s |
| CWS category fetch | interno | 10s |

Si el agente supera `AGENT_TIMEOUT_MS`, el job continúa sin veredicto IA — el reporte se genera igual con los hallazgos estáticos y las 13 categorías evaluadas.

## Archivos grandes (> 2 MB)

Los archivos que superan 2 MB no se procesan con AST. En su lugar:
- `skippedAst: true`
- Se extraen URLs y dominios con regex
- Se ejecutan las `grepSignals` (patrones críticos predefinidos)
- `chromeApis` se extrae con regex directamente (sin árbol sintáctico)
- Los permisos encontrados en `chromeApis` sí se registran como "usados"
- Los findings se emiten como `grep_signal_large_file`
