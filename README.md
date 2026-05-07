# Ext-Sandbox

**Plataforma de Análisis de Riesgo para Extensiones de Navegador**

Sistema backend que evalúa el nivel de riesgo de extensiones de Chrome mediante análisis estático (AST) y dinámico (Playwright en sandbox Docker), generando reportes tipo "Privacy Labels" con evidencia forense.

---

## Arquitectura

```
┌─────────────────────────────────────────────────────────────────┐
│  api_net                                                        │
│  ┌─────────────────┐     ┌─────────────────────────────────┐   │
│  │  Container 1    │────▶│  Container 2a: PostgreSQL       │   │
│  │  API + Core     │     │  Container 2b: Redis (BullMQ)   │   │
│  │  NestJS/TS      │     │  (jobs + reports)               │   │
│  │  Port: 3000     │     └──────────────┬──────────────────┘   │
│  └─────────────────┘                    │ Redis + PostgreSQL    │
└────────────────────────────────────────-│-────────────────────-┘
                                          │
┌─────────────────────────────────────────│───────────────────────┐
│  sandbox_net                            │                        │
│  ┌──────────────────────────────────────▼───────────────────┐   │
│  │  Container 3 - Worker Sandbox                            │   │
│  │  Playwright + Chromium headless                          │   │
│  │  Escribe resultados a PostgreSQL — sin acceso a API      │   │
│  └──────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────┘
```

## Pipeline de Análisis

```
POST /analyze  →  Queue (BullMQ)  →  Download .crx
     │                                     │
     ◀── jobId (HTTP 202)           Static Analysis (AST)
                                          │
                              ┌───────────┴───────────┐
                         Deobfuscation          Domain Discovery
                         (Base64/eval)          (Code PRIMARY source)
                                          │
                                  Strategy Selection
                           ┌──────────────┼──────────────┐
                        Level 1        Level 2         Level 3
                      Direct Nav    State Injection   Passive Trigger
                                                    + DOM Falsification
                                          │
                                  Dynamic Analysis
                                  (Playwright Sandbox)
                                  · Chrome API Proxy (addInitScript)
                                  · MutationObserver + Screenshots
                                  · Network Interception
                                          │
                              Threat Intelligence
                         (VT + URLScan + AbuseIPDB)
                         ← dominios estáticos + URLs dinámicas
                                          │
                             Privacy Labels Report
                         + contactedUrlsReputation
                         + dynamicEvidence.apiCalls
                         + dynamicEvidence.screenshotPaths
```

---

## Ejecución Local (Docker)

### Requisitos

- [Docker Engine](https://docs.docker.com/engine/install/) >= 24
- Docker Compose v2+ (incluido en Docker Desktop)
- Git

### Paso 1 — Clonar y entrar al proyecto

```bash
git clone <url-del-repo>
cd ext-sandbox
```

### Paso 2 — Configurar variables de entorno

```bash
cp .env.example .env
```

El archivo `.env.example` ya incluye valores por defecto funcionales para desarrollo local. Opcionalmente agrega tus API keys de Threat Intelligence:

```bash
# Editar .env y completar (opcionales, el sistema funciona sin ellas en modo degradado):
VIRUSTOTAL_API_KEY=tu_key_aqui    # https://www.virustotal.com/gui/my-apikey
URLSCAN_API_KEY=tu_key_aqui       # https://urlscan.io/user/profile/
ABUSEIPDB_API_KEY=tu_key_aqui     # https://www.abuseipdb.com/account/api
```

> **Nota sobre secrets del CI/CD:** `DB_PASSWORD`, `REDIS_PASSWORD` y `HONEYPOT_ENCRYPTION_KEY`
> son para el `.env` local. En GitHub Actions **no necesitas configurar ningún secret manualmente**
> — `GITHUB_TOKEN` es provisto automáticamente por GitHub.

### Paso 3 — Levantar todos los servicios

```bash
docker compose up -d
```

Esto levanta 4 contenedores: PostgreSQL, Redis, API (puerto 3000) y Worker Sandbox.
La primera vez tarda ~3-5 minutos porque descarga la imagen de Playwright con Chromium.

Verifica que todos estén saludables:

```bash
docker compose ps
# Todos deben mostrar "healthy" o "running"
```

### Paso 4 — Verificar que la API responde

```bash
curl http://localhost:3000/health
# Respuesta esperada:
# { "status": "ok", ... }
```

### Paso 5 — Enviar una extensión a analizar

```bash
# Ejemplo con "uBlock Origin" (ID público para pruebas)
curl -X POST http://localhost:3000/analyze \
  -H "Content-Type: application/json" \
  -d '{"extensionId": "cjpalhdlnbpafiamejdnhcphjbkeiagm"}'

# Respuesta HTTP 202:
# { "jobId": "550e8400-e29b-41d4-a716-446655440000", "status": "queued" }
```

### Paso 6 — Consultar estado del análisis

```bash
# El análisis tarda entre 30s y 5 minutos según la extensión
curl http://localhost:3000/status/550e8400-e29b-41d4-a716-446655440000

# Posibles estados:
# queued | downloading | static_analysis | dynamic_analysis |
# threat_intel | generating_report | completed | failed
```

### Paso 7 — Obtener el reporte final

```bash
curl http://localhost:3000/report/550e8400-e29b-41d4-a716-446655440000
```

El reporte es un JSON con Privacy Labels y evidencia forense completa:

```json
{
  "jobId": "550e8400-...",
  "extensionId": "cjpalhdlnbpafiamejdnhcphjbkeiagm",
  "overallRisk": "critical",
  "confidence": 0.85,
  "recommendation": "UNINSTALL IMMEDIATELY. This extension...",
  "privacyLabels": [
    {
      "category": "keylogger",
      "title": "Keystroke Monitoring",
      "description": "This extension monitors your keyboard activity...",
      "severity": "critical",
      "evidence": ["Registers keyboard event listeners (content.js:61)"]
    }
  ],
  "staticFindings": [
    { "category": "data_theft", "severity": "critical",
      "description": "Accesses cookies", "location": { "file": "1.js", "line": 1464 } }
  ],
  "contactedUrls": ["https://api.example.com/sync"],
  "contactedUrlsReputation": [
    {
      "url": "https://api.example.com/sync",
      "hostname": "api.example.com",
      "isMalicious": true,
      "score": 0.87,
      "providers": ["virustotal", "urlscan"],
      "categories": ["malware"]
    }
  ],
  "abusedPermissions": ["tabs", "webRequest", "cookies"],
  "dynamicEvidence": {
    "networkRequests": [
      { "url": "https://api.example.com/sync", "method": "POST",
        "body": "{\"credentials\":\"...\"}", "origin": "extension" }
    ],
    "domMutations": [
      { "type": "childList", "target": "SCRIPT", "timestamp": 1234567890 }
    ],
    "apiCalls": [
      { "api": "chrome.storage.local.get", "args": "[\"passwords\"]", "timestamp": 1234567890 },
      { "api": "fetch", "args": "[\"https://api.example.com/sync\", {\"method\":\"POST\"}]", "timestamp": 1234567891 }
    ],
    "screenshotPaths": [
      "/tmp/ext-sandbox/screenshots/550e8400/dom_falsification_0_script_injection.png",
      "/tmp/ext-sandbox/screenshots/550e8400/dom_falsification_1_final.png"
    ]
  },
  "threatIntelResults": [ ... ],
  "analysisDuration": 45230
}
```

### Monitorear el progreso en tiempo real

Ver los logs del worker (donde ocurre el análisis):

```bash
docker compose logs -f worker
```

Ver los logs de la API (donde llegan las peticiones HTTP):

```bash
docker compose logs -f api
```

Ver ambos a la vez:

```bash
docker compose logs -f api worker
```

Ver todos los jobs en cola:

```bash
# Linux / macOS / Git Bash
curl http://localhost:3000/analysis

# PowerShell
(Invoke-WebRequest -Uri "http://localhost:3000/analysis").Content | ConvertFrom-Json | ConvertTo-Json -Depth 5
```

Ver el estado de un job específico con respuesta formateada:

```bash
# Linux / macOS / Git Bash
curl http://localhost:3000/analysis/<jobId>

# PowerShell
(Invoke-WebRequest -Uri "http://localhost:3000/analysis/<jobId>").Content | ConvertFrom-Json | ConvertTo-Json -Depth 10
```

### Detener el sistema

```bash
docker compose down          # Para y elimina contenedores (datos persisten)
docker compose down -v       # Elimina también los volúmenes (borra BD)
```

---

## Conexión desde una Extensión de Chrome

El backend corre en `http://localhost:3000` cuando lo ejecutas con Docker localmente.
Para consumir esta API desde tu extensión, agrega esto al `manifest.json` de la extensión:

```json
{
  "host_permissions": ["http://localhost:3000/*"]
}
```

Luego desde el código de la extensión (background script o popup):

```javascript
const response = await fetch('http://localhost:3000/analyze', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ extensionId: 'id-de-la-extension-a-analizar' })
});
const { jobId } = await response.json(); // HTTP 202

// Polling del estado (cada 30s recomendado)
const status = await fetch(`http://localhost:3000/status/${jobId}`);

// Reporte final
const report = await fetch(`http://localhost:3000/report/${jobId}`);
```

> CORS está habilitado en el backend (`app.enableCors()`), por lo que no hay restricciones
> de origen. En producción (cloud), reemplaza `localhost:3000` con la URL del servidor.

---

## Ejecución de Tests

Los tests son unitarios y no requieren Docker ni base de datos.

```bash
# Instalar dependencias (solo primera vez)
npm install

# Tests unitarios
npm test

# Tests con reporte de cobertura (mínimo 70% — RNF06)
npm run test:cov

# El reporte HTML de cobertura se genera en coverage/lcov-report/index.html
```

---

## API REST — Referencia Completa

### `POST /analyze` — Enviar extensión (RF01)

```
POST http://localhost:3000/analyze
Content-Type: application/json

{ "extensionId": "cjpalhdlnbpafiamejdnhcphjbkeiagm" }
```

- Respuesta `202`: `{ "jobId": "uuid", "status": "queued" }`
- Respuesta `400`: ID inválido (debe ser 32 letras minúsculas)

### `GET /status/:jobId` — Estado del análisis

```
GET http://localhost:3000/status/:jobId
```

Posibles valores de `status`:
`queued` | `downloading` | `static_analysis` | `dynamic_analysis` | `threat_intel` | `generating_report` | `completed` | `failed`

### `GET /report/:jobId` — Reporte Privacy Labels

```
GET http://localhost:3000/report/:jobId
```

### `GET /health` — Health check (RNF05)

```
GET http://localhost:3000/health
```

---

## Patrones Detectados (RF03)

| Categoría | Severidad | Ejemplo |
|-----------|-----------|---------|
| Robo de datos | CRITICAL | `document.querySelector('input[type="password"]')` |
| Keylogger | CRITICAL | `addEventListener('keyup', ...)` |
| Inyección de scripts | CRITICAL | `document.createElement('script')` |
| Exfiltración | CRITICAL | `navigator.sendBeacon(...)`, `fetch()` externo |
| Dominios objetivo | CRITICAL | URLs bancarias/gubernamentales hardcodeadas |
| Persistencia | MEDIUM | `chrome.alarms.create(...)` |

## Estrategias de Detonación — Análisis Dinámico (Sección 9)

Todas las extensiones pasan por análisis dinámico. La estrategia se selecciona según los dominios detectados en el análisis estático:

| Nivel | Plataformas | Estrategia |
|-------|-------------|------------|
| Nivel 1 | YouTube, Wikipedia, Reddit | Navegación directa |
| Nivel 2 | Facebook, Instagram, Gmail | Inyección de storageState cifrado (honeypot) |
| Nivel 3 | Bancos, Gobierno, Salud | Passive trigger + DOM Falsification con credenciales honeypot |

### DOM Falsification (Nivel 3)

Para extensiones que apuntan a plataformas bancarias o gubernamentales, el sistema genera una página HTML falsa que replica la estructura de formularios de login (mismos selectores CSS/IDs que el código de la extensión referencia). Se inyectan credenciales honeypot en los campos:

```html
<input type="text" name="username" value="testuser@example.com" />
<input type="password" name="password" value="honeypot-password-123" />
```

Si la extensión captura y exfiltra estas credenciales, el request aparece en `contactedUrls` y `dynamicEvidence.networkRequests` con el body capturado — evidencia forense directa.

## Capacidades del Análisis Dinámico

### Intercepción de APIs Chrome (`addInitScript`)

Antes de cargar cualquier script de la extensión, se instalan Proxies sobre las APIs de Chrome en el mundo principal de la página:

| API interceptada | Qué registra |
|-----------------|-------------|
| `chrome.storage.local.*` | Claves leídas/escritas y sus valores |
| `chrome.storage.sync.*` | Sincronización de datos entre dispositivos |
| `chrome.runtime.sendMessage` | Mensajes internos de la extensión |
| `chrome.tabs.query/sendMessage` | Acceso y comunicación entre tabs |
| `chrome.cookies.get/set/getAll` | Lectura y escritura de cookies |
| `fetch()` | URL, método y preview del body enviado |
| `XMLHttpRequest` | URL y método de cada request XHR |

> Aplica a content scripts en mundo MAIN. `fetch` y `XMLHttpRequest` se interceptan siempre.

### Detección de Mutaciones DOM

Un `MutationObserver` monitorea la página durante el análisis. Se detectan y registran:
- Inserción de elementos `<script src="...">` externos
- Inserción de `<iframe>` 
- Modificaciones de HTML via `innerHTML`

Las mutaciones **críticas** (script o iframe) disparan un screenshot automático inmediato.

### Capturas de Pantalla Automáticas

El sistema toma screenshots en dos momentos:

1. **Mutación crítica** — inmediatamente al detectar inserción de script externo o iframe
2. **Estado final** — al terminar el tiempo de espera del plan de análisis

Las rutas se incluyen en `dynamicEvidence.screenshotPaths`. Para acceder durante una sesión activa:

```bash
docker exec ext-sandbox-worker ls /tmp/ext-sandbox/screenshots/<jobId>/
```

---

## Stack Tecnológico

- **Runtime**: Node.js 24 + TypeScript
- **Framework**: NestJS
- **Parser AST**: @babel/parser + @babel/traverse
- **Cola**: Redis + BullMQ
- **Base de datos**: PostgreSQL + TypeORM
- **Análisis dinámico**: Playwright (Chromium headless)
- **Threat Intel**: VirusTotal, URLScan.io, AbuseIPDB
- **Contenedores**: Docker + Docker Compose
- **CI/CD**: GitHub Actions

## Seguridad (RNF01)

- Análisis dinámico en contenedor efímero con tmpfs (sin persistencia en disco)
- Red `sandbox_net` aislada — worker sin visibilidad al Container 1 (API HTTP)
- Seccomp profile para restricción de syscalls en Chrome (`seccomp/chrome.json`) — incluye `clone3` para Node.js 24
- Contenedores sin privilegios (`no-new-privileges:true`)
- cgroups: límite 2 CPU + 2 GB RAM por worker
- StorageState de honeypot cifrado AES-256-GCM
- Sin bind mounts al host (RNF01)

---

## Variables de Entorno

| Variable | Descripción | Requerida | Default (dev) |
|----------|-------------|-----------|---------------|
| `DB_PASSWORD` | Contraseña de PostgreSQL | Sí | `extsandbox_secret` |
| `REDIS_PASSWORD` | Contraseña de Redis | Sí | `redis_secret` |
| `HONEYPOT_ENCRYPTION_KEY` | Clave AES-256 para storageState (mín 32 chars) | Sí | ver `.env.example` |
| `VIRUSTOTAL_API_KEY` | API key de VirusTotal | Recomendada | vacío (modo degradado) |
| `URLSCAN_API_KEY` | API key de URLScan.io | Opcional | vacío |
| `ABUSEIPDB_API_KEY` | API key de AbuseIPDB | Opcional | vacío |
| `STATIC_TIMEOUT_MS` | Timeout análisis estático | No | `60000` |
| `DYNAMIC_TIMEOUT_MS` | Timeout análisis dinámico | No | `180000` |

> Los valores por defecto de `.env.example` son suficientes para ejecutar y probar localmente.
> Cambia las contraseñas antes de cualquier despliegue en producción.

---

## Troubleshooting

**Conflicto de nombre de contenedor al hacer `docker compose up --build`:**
```bash
docker compose down   # baja todo antes de rebuildar
docker compose up -d --build
```

**Docker no inicia el worker (exit code 139):**
Verificar que `seccomp/chrome.json` incluya `clone3` en la lista de syscalls permitidos. Node.js 24 lo requiere para crear threads.
```bash
docker compose logs worker   # ver error específico
grep clone3 seccomp/chrome.json   # debe aparecer
```

**La imagen de Playwright tarda mucho:**
La primera `docker compose up` descarga ~1.5 GB (Chromium incluido). Esperar es normal.

**El análisis queda en `downloading` y no avanza:**
Verifica conectividad a internet desde los contenedores:
```bash
docker compose exec api curl -I https://clients2.google.com
```

**El análisis queda en `threat_intel` por mucho tiempo:**
Normal para extensiones con muchos dominios detectados (URLScan.io puede tardar hasta 10s por dominio). Si no hay API keys, el sistema opera en modo degradado pero sigue consultando URLScan.io sin autenticación.

**Tests fallan localmente:**
```bash
npm install   # asegurarse de tener dependencias instaladas
npm test      # los tests son unitarios, no necesitan Docker
```
