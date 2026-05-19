# Arquitectura

## Contenedores Docker

```
┌─────────────────────────────────────────────────────────────┐
│  api_net                                                    │
│  ┌──────────────────┐    ┌──────────────────────────────┐  │
│  │  api             │───▶│  postgres:16-alpine          │  │
│  │  NestJS, :3000   │    │  redis:7-alpine              │  │
│  └──────────────────┘    └──────────────┬───────────────┘  │
└─────────────────────────────────────────│───────────────────┘
                                          │ DB + Queue
┌─────────────────────────────────────────│───────────────────┐
│  sandbox_net                            │                    │
│  ┌──────────────────────────────────────▼─────────────────┐ │
│  │  worker                                                │ │
│  │  BullMQ processor — sin acceso a la API               │ │
│  │  tmpfs /tmp/ext-sandbox (512 MB, efímero)             │ │
│  └────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────┘
```

El worker corre en `sandbox_net` — red separada que no puede ver al contenedor `api`. La comunicación entre ambos ocurre exclusivamente a través de Redis (cola) y PostgreSQL (resultados).

## Módulos NestJS

| Módulo | Responsabilidad |
|--------|-----------------|
| `AnalysisModule` | Controladores HTTP `/analyze`, `/status`, `/report` |
| `QueueModule` | `AnalysisProcessor` — BullMQ consumer del pipeline |
| `DownloaderModule` | Descarga y extracción de `.crx` desde Chrome Web Store |
| `PreprocessorModule` | Parsing de manifest, clasificación de archivos, extracción de URLs |
| `StaticAnalysisModule` | AST (Babel), taint analysis, deobfuscación, patrones de riesgo |
| `AgentsModule` | Agent1 LLM holístico + cliente Ollama |
| `ReportModule` | Construcción del reporte final + UserRiskSummary (13 categorías) |
| `ThreatIntelModule` | Consultas a VirusTotal |
| `HealthModule` | `/health` y `/health/ready` |

## Recursos por contenedor

| Contenedor | CPU | Memoria | Red |
|------------|-----|---------|-----|
| api | sin límite | 512 MB | api_net |
| worker | 2.0 CPUs | 1024 MB | sandbox_net |
| postgres | sin límite | 256 MB | api_net + sandbox_net |
| redis | sin límite | 256 MB | api_net + sandbox_net |

## Stack tecnológico

- **Runtime**: Node.js 24 + TypeScript (ESM)
- **Framework**: NestJS 11
- **Cola**: BullMQ + Redis 7
- **Base de datos**: PostgreSQL 16 + TypeORM
- **Parser AST**: @babel/parser + @babel/traverse
- **LLM local**: Ollama (`qwen3:8b` por defecto)
- **Contenedores**: Docker Compose v2
