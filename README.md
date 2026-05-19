# Extension Warden — Backend

Backend de análisis estático + IA para extensiones de Chrome. Descarga la extensión, audita su código con AST y LLM, y genera un reporte de riesgo estructurado.

## Inicio rápido

```bash
cp .env.example .env          # completar OLLAMA_HOST y DB/Redis passwords
docker compose up -d
curl http://localhost:3000/health
```

## Endpoints principales

| Método | Path | Descripción |
|--------|------|-------------|
| `POST` | `/analyze` | Analiza extensión por ID de Chrome Web Store |
| `POST` | `/analyze/upload` | Analiza un archivo `.crx` o `.zip` local |
| `GET`  | `/status/:jobId` | Estado del análisis |
| `GET`  | `/report/:jobId` | Reporte completo (solo si `COMPLETED`) |
| `GET`  | `/health` | Liveness probe |
| `GET`  | `/health/ready` | Readiness probe (DB + Redis) |

```bash
# Enviar extensión
curl -X POST http://localhost:3000/analyze \
  -H "Content-Type: application/json" \
  -d '{"extensionId": "cjpalhdlnbpafiamejdnhcphjbkeiagm"}'
# → { "jobId": "uuid", "status": "queued" }

# Consultar reporte
curl http://localhost:3000/report/<jobId>
```

## Variables de entorno clave

| Variable | Descripción | Default |
|----------|-------------|---------|
| `OLLAMA_HOST` | URL del servidor Ollama | `http://host.docker.internal:11434` |
| `MODELO_OLLAMA` | Modelo LLM local | `qwen3:8b` |
| `AGENT_TIMEOUT_MS` | Timeout del análisis IA | `900000` |
| `DB_PASSWORD` | Contraseña PostgreSQL | ver `.env.example` |
| `REDIS_PASSWORD` | Contraseña Redis | ver `.env.example` |
| `VIRUSTOTAL_API_KEY` | API key para Threat Intel | opcional |

Ver `.env.example` para la lista completa.

## Tests

```bash
npm install
npm test          # 85+ tests unitarios (no requieren Docker)
npm run test:cov  # con cobertura
```

## Documentación

Ver [docs/](docs/) para documentación técnica completa:

- [Arquitectura](docs/architecture.md) — pipeline, módulos, Docker
- [Pipeline de análisis](docs/pipeline.md) — etapas, estados, timeouts
- [API Reference](docs/api.md) — contratos de request/response
- [Análisis estático](docs/static-analysis.md) — AST, patrones, discovery types
- [Agente IA](docs/agent.md) — prompt, veredictos, categorías de riesgo
- [Variables de entorno](docs/env.md) — referencia completa
