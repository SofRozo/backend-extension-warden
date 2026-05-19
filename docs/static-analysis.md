# Análisis Estático

El módulo `StaticAnalysisModule` procesa los archivos JavaScript de la extensión con tres técnicas combinadas: AST parsing, taint analysis y pattern matching. Su salida es una lista de hallazgos técnicos (`resultado1`) que alimentan tanto el `UserRiskSummary` como el agente IA.

## Etapas

### 1. AST Parsing (Babel)

Cada archivo con `cleanCode` disponible se parsea con `@babel/parser`. Se detectan:
- Llamadas a APIs Chrome (`chrome.*`)
- Patrones de acceso a datos sensibles (cookies, storage, formularios)
- Operaciones de red (fetch, XHR, sendBeacon)
- Creación dinámica de código (eval, new Function, setTimeout con string)
- Listeners de eventos de teclado
- Manipulación del DOM (innerHTML, createElement('script'))
- Hooking de prototipos (XMLHttpRequest.prototype, navigator.geolocation)

Cada hallazgo registra: `filePath`, `line`, `discoveryType`, `detail`, `codeSnippet` (fragmento real del código, ≤ 120 chars) y `confidence`.

### 2. Taint Analysis

Rastrea flujos de datos sensibles desde fuentes hasta sinks de red:

**Fuentes** (datos sensibles): campos de formulario, cookies, localStorage, `document.body`, selectores de contraseñas.

**Sinks** (salida de datos): `fetch()`, `XMLHttpRequest.send()`, `chrome.runtime.sendMessage()`, `navigator.sendBeacon()`.

Si un dato sensible llega a un sink de red → finding `flujo_datos_a_red`.

### 3. Deobfuscación

Antes del AST parsing, se intenta deobfuscación de:
- Strings Base64 (`atob`, `btoa`)
- Cadenas de `eval()`
- Funciones autoejecutorias con encoding

### 4. Correlación de riesgos

Tras analizar todos los archivos, se correlacionan hallazgos para detectar combinaciones especialmente peligrosas (ej. `webRequest` + `proxy` + `management` juntos).

## Discovery Types (Resultado 1)

| Tipo | Descripción | Severidad típica |
|------|-------------|-----------------|
| `permiso_chrome_manifest_riesgoso` | Permiso crítico declarado (proxy, management, etc.) | high/critical |
| `permiso_chrome_manifest_no_usado` | Permiso declarado pero sin uso detectado en código | medium |
| `flujo_datos_a_red` | Datos sensibles → sink de red (taint) | critical |
| `lectura_cookies` | Acceso a `document.cookie` | high |
| `listener_teclado` | `addEventListener('keydown'/'keypress'/'keyup')` | high |
| `inyeccion_dom` | `innerHTML`, `createElement('script')`, `insertAdjacentHTML` | high |
| `interceptacion_api` | Hook sobre fetch, XHR, history, geolocation | high |
| `suplantacion_api_navegador` | Override de `navigator.*`, geolocation spoofing | high |
| `funcion_javascript_riesgosa` | `eval`, `new Function`, `setTimeout(string)` | high |
| `lectura_storage_navegador` | `localStorage`, `sessionStorage` | medium |
| `codigo_ofuscado` | Archivo identificado como obfuscado | medium |
| `archivo_minificado` | Archivo minificado (menor legibilidad) | low |
| `archivo_huerfano` | Archivo no referenciado en manifest ni importado | medium |
| `grep_signal_large_file` | Señal en archivo > 2 MB (solo regex, sin AST) | medium |
| `script_remoto_mv3` | `<script src="...">` externo en HTML (violación MV3) | critical |
| `dependencia_no_resuelta` | Import/require con path no encontrado | low |
| `correlacion_riesgo` | Combinación de hallazgos que juntos elevan el riesgo | high/critical |
| `navegacion_externa_sensible` | URL con contexto financiero/gov/id hardcodeada | medium |

## Domain Discovery Types (Resultado 2)

| Tipo | Descripción |
|------|-------------|
| `url_en_codigo` | URL encontrada en código fuente o strings |
| `host_permission_manifest` | Dominio declarado en `host_permissions` del manifest |

## Categorías de dominio

Los dominios detectados se clasifican automáticamente:

| Categoría | Ejemplos |
|-----------|---------|
| `propio_extension` | Dominio del desarrollador (inferido por contexto) |
| `infraestructura_tecnica` | AWS, Firebase, Cloudflare, CDNs |
| `sensible_financiero` | Bancos, PayPal, exchanges crypto |
| `sensible_identidad` | Google, Microsoft, servicios de identidad |
| `sensible_redes_sociales` | Facebook, Instagram, Twitter/X |
| `sensible_correo_productividad` | Gmail, Outlook, Slack |
| `sensible_gubernamental` | `.gov`, servicios de gobierno |
| `sensible_llm` | OpenAI, Anthropic, Gemini |
| `sensible_data_broker` | Agregadores de datos |
| `desconocido` | No clasificado automáticamente |

## Archivos grandes (> 2 MB)

Los archivos que superan 2 MB no se procesan con AST para evitar timeouts de memoria. En cambio:

1. Se ejecuta un scan de regex (`extractGrepSignals`) con ~25 patrones críticos predefinidos.
2. Se extraen `chromeApis` con regex (sin árbol sintáctico) — los permisos encontrados sí se registran como "usados".
3. Las señales encontradas generan findings de tipo `grep_signal_large_file`.

Esto evita falsos positivos en `permiso_chrome_manifest_no_usado` para extensiones con bundles grandes donde el AST no pudo procesar el código.

## UserRiskSummary — Las 13 categorías de riesgo

Tras el análisis estático, `UserRiskSummaryService` agrupa los hallazgos en 13 categorías temáticas. Cada evaluador recibe:
- Los hallazgos estáticos positivos (`positives`)
- Las API Chrome realmente invocadas en el código (`apiCalls`)
- Los permisos declarados en el manifest (`perms`)
- El contexto de host amplio (`broadHost`)

Cada categoría produce un `UserRiskSummaryItem` con:

| Campo | Contenido |
|-------|-----------|
| `id` | Identificador de la categoría |
| `estado` | `no_detectado` / `capacidad` / `sospechoso` / `critico` |
| `resumen` | Frase en lenguaje cotidiano sobre lo detectado |
| `evidencias` | Lista de textos explicativos (máx 5) |
| `hallazgos_codigo` | Hallazgos con `filePath`, `line`, `fileType`, `texto` y `codeSnippet` |

**Importante:** el `estado` es una clasificación determinista basada en patrones de código. No tiene en cuenta el propósito declarado de la extensión — eso es tarea del agente IA.

### Las 13 categorías

| ID | Título |
|----|--------|
| `acceso_general_navegador` | Acceso general al navegador |
| `modificacion_paginas` | Modificación de páginas |
| `lectura_informacion` | Lectura de información en páginas |
| `captura_credenciales` | Contraseñas, tokens y sesiones |
| `keylogging` | Registro de teclas |
| `seguimiento_privacidad` | Seguimiento y privacidad |
| `manipulacion_trafico` | Manipulación de tráfico |
| `acceso_historial` | Historial de navegación |
| `descargas_archivos` | Descargas y archivos |
| `ofuscacion_transparencia` | Ofuscación y transparencia |
| `abuso_management` | Abuso de APIs de administración |
| `mineria_recursos` | Minería de recursos |
| `fingerprinting_severo` | Fingerprinting del dispositivo |

### Qué se muestra al usuario en la UI

El frontend muestra las 13 categorías en un bloque colapsable "Señales por categoría". Para cada una:
- Badge de estado con color (`critico` → rojo, `sospechoso` → naranja, `capacidad` → azul, `no_detectado` → gris)
- El resumen en lenguaje cotidiano
- Los `hallazgos_codigo`: archivo, línea y descripción de cada hallazgo concreto

Este bloque muestra los **hechos técnicos** — no el juicio final. El veredicto con contexto es responsabilidad del agente IA.
