# Variables de Entorno

Copiar `.env.example` como punto de partida:

```bash
cp .env.example .env
```

## Requeridas para funcionar

| Variable | Descripción | Default dev |
|----------|-------------|-------------|
| `DB_PASSWORD` | Contraseña PostgreSQL | `extsandbox_secret` |
| `REDIS_PASSWORD` | Contraseña Redis | `redis_secret` |
| `OLLAMA_HOST` | URL del servidor Ollama | `http://host.docker.internal:11434` |

## LLM / Agente

| Variable | Descripción | Default |
|----------|-------------|---------|
| `MODELO_OLLAMA` | Modelo Ollama a usar | `qwen3:8b` |
| `AGENT_TIMEOUT_MS` | Timeout del agente LLM (ms) | `900000` (15 min) |

`AGENT_TIMEOUT_MS` controla cuánto espera el worker antes de continuar sin veredicto IA. El timeout de Axios al LLM es `AGENT_TIMEOUT_MS + 90000` ms para garantizar que el job-level timeout dispare primero.

## Base de datos

| Variable | Descripción | Default |
|----------|-------------|---------|
| `DB_HOST` | Host PostgreSQL | `localhost` |
| `DB_PORT` | Puerto PostgreSQL | `5432` |
| `DB_USERNAME` | Usuario PostgreSQL | `extsandbox` |
| `DB_NAME` | Nombre de la base de datos | `extsandbox` |

## Redis / Cola

| Variable | Descripción | Default |
|----------|-------------|---------|
| `REDIS_HOST` | Host Redis | `localhost` |
| `REDIS_PORT` | Puerto Redis | `6379` |

## Timeouts del pipeline

| Variable | Descripción | Default |
|----------|-------------|---------|
| `STATIC_TIMEOUT_MS` | Timeout análisis estático completo | `60000` (1 min) |
| `analysis.preprocessTimeoutMs` | Timeout de preprocessing | `30000` (30s) |

## Threat Intelligence (opcional)

| Variable | Descripción |
|----------|-------------|
| `VIRUSTOTAL_API_KEY` | API key de VirusTotal (sin clave → modo degradado) |

> URLScan.io y AbuseIPDB tienen código de integración pero no están conectados al pipeline activo.

## Servidor

| Variable | Descripción | Default |
|----------|-------------|---------|
| `PORT` | Puerto HTTP de la API | `3000` |
| `NODE_ENV` | Entorno (`development` / `production`) | `development` |
| `MAX_CONCURRENT_WORKERS` | Workers BullMQ concurrentes | `10` |

## Notas de producción

- Cambiar `DB_PASSWORD` y `REDIS_PASSWORD` antes de cualquier despliegue.
- `OLLAMA_HOST` debe apuntar al servidor Ollama accesible desde el contenedor worker. En Docker Desktop (Windows/Mac) `host.docker.internal` resuelve al host. En Linux usar la IP del host o un contenedor dedicado.
- El modelo `qwen3:8b` requiere ~8 GB de RAM para el KV cache con `num_ctx: 8192`. Modelos más pequeños pueden funcionar con `num_ctx` menor.
