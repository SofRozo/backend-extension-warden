# Reglas implementadas de análisis estático para extensiones Chrome

Este documento describe lo que el backend verifica hoy de forma determinista en el análisis estático. Su objetivo es complementar el puntaje inicial del frontend: el frontend mide superficie de riesgo por permisos; el backend revisa qué hace realmente el código empaquetado.

## Principio central

Una extensión no se marca como maliciosa por un único permiso, una única URL o una llamada genérica. El backend combina:

- Permisos y estructura del `manifest.json`.
- Rol del archivo: `content_script`, `background`, `popup`, `options_ui`, `devtools`, `sandbox`, `override_page`, `side_panel`, `library`, `unknown`.
- Fuentes sensibles: cookies, credenciales, DOM, storage, historial/tabs, identidad, clipboard, capturas y datos de extensiones instaladas.
- Sinks: red externa, WebSocket/EventSource, `sendBeacon`, native messaging, mensajería interna, ejecución dinámica e inyección DOM/script.
- Contexto del dominio: contacto real de red vs link de navegación, dominio propio, infraestructura técnica, dominio sensible o desconocido.
- Correlaciones: mismo archivo, flujo AST intraarchivo y patrón content script -> mensaje -> background -> red.

## Salida del SAST

El análisis estático llena:

- `resultado1`: hallazgos de código/manifest que no son dominios.
- `resultado2_priority`: dominios sensibles detectados en código contactado o `host_permissions`.
- `resultado2_unknown`: dominios desconocidos contactados o declarados.
- `riskScore`: puntaje agregado y razones principales.

Cada hallazgo está enriquecido con:

- `severity`: `low`, `medium`, `high`, `critical`.
- `confidence`: confianza determinista del hallazgo.
- `why`: explicación técnica corta.
- `scoreImpact`: contribución aproximada al riesgo.
- `codeSnippet`: fragmento cuando el AST puede ubicarlo.

El reporte final convierte esos datos en explicaciones entendibles para usuario, por ejemplo: qué archivo lo hizo, en qué línea, por qué importa, contexto del rol y confianza.

## Inventario implementado

Antes de aplicar reglas, el preprocesador:

1. Lee `manifest.json`.
2. Separa `permissions`, `host_permissions` y `optional_permissions`.
3. Identifica `content_scripts`, background/service worker, popup, options, devtools, side panel, sandbox y overrides.
4. Lee `web_accessible_resources`, `externally_connectable`, `oauth2` y archivos de reglas `declarative_net_request`.
5. Construye grafo de dependencias desde manifest, HTML, imports, dynamic import, `require`, workers, `chrome.scripting.executeScript({ files })` y asignaciones locales a `.src`.
6. Clasifica archivos por rol.
7. Detecta archivos huérfanos, dependencias no resueltas, archivos anidados, minificación y ofuscación.
8. Extrae APIs `chrome.*`, URLs, dominios y señales de red.

## Permisos evaluados

El backend clasifica permisos en bajo, medio, alto o crítico. Un permiso aislado queda con baja confianza; sube cuando aparece combinado con comportamiento real en código.

### Permisos críticos

| Permiso                                       | Tratamiento                                                                                           |
| --------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| `<all_urls>`, `*://*/*`                       | Crítico como capacidad, pero no confirma abuso por sí solo. Sube con DOM/cookies/credenciales + sink. |
| `tabCapture`, `pageCapture`, `desktopCapture` | Crítico/alto; sube si hay sink de red.                                                                |
| `debugger`                                    | Crítico; sube con red o extracción de datos.                                                          |
| `nativeMessaging`                             | Crítico; sube con red o datos sensibles.                                                              |
| `proxy`, `vpnProvider`                        | Crítico por capacidad de interceptar/redirigir tráfico.                                               |

### Permisos altos

| Permiso                                                                                                                                                | Tratamiento                                                        |
| ------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------ |
| `cookies`                                                                                                                                              | Alto; crítico si cookies fluyen a red/mensajería/native messaging. |
| `scripting`, `userScripts`                                                                                                                             | Alto; sube con inyección, URL sospechosa u ofuscación.             |
| `webRequest`, `webRequestBlocking`                                                                                                                     | Alto; sube con `<all_urls>`, red u ofuscación.                     |
| `declarativeNetRequest`, `declarativeNetRequestWithHostAccess`                                                                                         | Alto; se revisan reglas de redirección/amplitud.                   |
| `history`, `downloads`, `privacy`, `browsingData`, `contentSettings`, `webNavigation`, `webAuthenticationProxy`, `certificateProvider`, `platformKeys` | Alto; suben con sinks o correlaciones.                             |

### Permisos medios relevantes

| Permiso                                                                                 | Tratamiento                                     |
| --------------------------------------------------------------------------------------- | ----------------------------------------------- |
| `tabs`, `activeTab`                                                                     | Medio; sube con inyección, lectura o red.       |
| `clipboardRead`, `clipboardWrite`                                                       | Medio; sube si hay flujo a red.                 |
| `identity`, `identity.email`                                                            | Medio; sube si tokens/email fluyen fuera.       |
| `management`, `sessions`, `topSites`, `bookmarks`, `geolocation`, `alarms`, `offscreen` | Medio; suben por combinación con fuentes/sinks. |

## Reglas por rol de archivo

### Content script

Se considera el rol más sensible porque corre dentro de páginas visitadas.

Reglas implementadas:

- Lectura de cookies, credenciales, DOM o storage en content script sube confianza.
- Listener `keydown`, `keyup`, `keypress`, `input`, `change` o `submit` en content script es sospechoso; con sink en el mismo archivo se vuelve fuerte.
- Inyección DOM/script en content script es sospechosa; con sink o script remoto se vuelve fuerte.
- Fuente sensible que llega a `fetch`, XHR, WebSocket, `sendBeacon`, native messaging o mensajería interna se reporta como flujo.

### Background/service worker

Reglas implementadas:

- Detecta sinks de red y mensajería.
- Detecta uso de APIs privilegiadas como cookies, history, tabs, identity, downloads, management, capture y scripting.
- Correlaciona mensajes desde content script con `fetch` en background como ruta probable de exfiltración interarchivo.

### Popup/options/side panel/devtools

Reglas implementadas para reducir falsos positivos:

- Listeners de teclado en UI sin sink se descartan.
- `innerHTML`/DOM injection en UI sin sink se descarta como render normal.
- `chrome.storage` en UI sin sink se descarta como estado local normal.
- Links a redes sociales, soporte o documentación no cuentan como contacto de red.

### Sandbox/override/unknown

Reglas implementadas:

- Sandbox se clasifica como rol propio; sus hallazgos se conservan con el contexto del archivo.
- Overrides se clasifican como rol propio si aparecen en manifest.
- Archivos `unknown` o huérfanos se reportan para auditoría, especialmente si contienen sinks u ofuscación.

## Fuentes sensibles implementadas

| Fuente                | Patrones soportados                                                                                                   |
| --------------------- | --------------------------------------------------------------------------------------------------------------------- |
| Cookies               | `document.cookie`, `chrome.cookies.get`, `chrome.cookies.getAll`                                                      |
| Credenciales          | Selectores con `password`, `token`, `auth`, `bearer`, `wallet`, `seed`, `privatekey`, `metamask`; lectura de `.value` |
| DOM visible           | `innerText`, `textContent`, `innerHTML`, `document.body`, `document.documentElement`, `document.forms`, selección DOM |
| Storage               | `localStorage`, `sessionStorage`, `indexedDB`, `chrome.storage.*`                                                     |
| Navegación            | `chrome.history.*`, `chrome.tabs.query`, `chrome.sessions.*`, `chrome.topSites.*`                                     |
| Identidad             | `chrome.identity.*`, `chrome.identity.launchWebAuthFlow`                                                              |
| Clipboard             | `navigator.clipboard.*`                                                                                               |
| Captura               | `chrome.tabs.captureVisibleTab`, permisos de capture                                                                  |
| Descargas/extensiones | `chrome.downloads.search`, `chrome.management.*`                                                                      |

## Sinks implementados

| Sink                                                                          | Tratamiento                                                                       |
| ----------------------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| `fetch`, `axios.*`                                                            | Sink de red.                                                                      |
| `XMLHttpRequest.open/send`                                                    | Contacto de red; `open` permite extraer dominio real.                             |
| `navigator.sendBeacon`                                                        | Sink de exfiltración fuerte.                                                      |
| `WebSocket`, `EventSource`                                                    | Canal persistente externo.                                                        |
| `chrome.runtime.sendNativeMessage`, `connectNative`                           | Salida hacia ejecutable local.                                                    |
| `chrome.identity.launchWebAuthFlow`                                           | Riesgoso cuando participa en flujo sensible.                                      |
| `chrome.runtime.sendMessage`, `chrome.tabs.sendMessage`, `window.postMessage` | Mensajería interna; no es red por sí sola, pero puede ser salto hacia background. |
| `eval`, `new Function`, `setTimeout(string)`, `setInterval(string)`           | Ejecución dinámica.                                                               |
| `document.createElement('script'/'iframe')` + `.src` remoto                   | Carga remota/inyección.                                                           |
| `document.write`, `innerHTML`, `outerHTML`, `script.src`                      | Inyección DOM/script.                                                             |

## Flujo de datos implementado

El AST rastrea taint intraarchivo para:

- `const x = document.cookie`
- `x = fuente`
- `payload.token = fuente`
- Destructuring: `const { token } = fuente`
- `await chrome.cookies.getAll()`
- Promesas: `chrome.cookies.getAll().then(cookies => ...)`
- `JSON.stringify(tainted)`
- Objetos, arrays, template literals y concatenaciones que contienen valores tainted
- Lecturas como `document.querySelector(...).value`

Reglas de flujo:

1. Fuente sensible -> sink de red en el mismo flujo: hallazgo crítico.
2. Fuente sensible -> mensajería interna: hallazgo de flujo con confianza media/alta.
3. Fuente sensible -> mensajería interna en content script + `fetch` en background: correlación fuerte de exfiltración interarchivo probable.

Importante: el motor no reconstruye todavía todo el payload interarchivo campo por campo; detecta la ruta probable cuando hay señales claras en ambos extremos.

## Dominios y falsos positivos

### Contacto real vs referencia

Solo se consideran dominios contactados cuando aparecen en:

- `fetch`
- `axios`
- `XMLHttpRequest.open`
- `WebSocket`
- `EventSource`
- `sendBeacon`
- `script.src`/`iframe.src` remotos creados dinámicamente

No se consideran contactos:

- `window.open("https://instagram.com/...")`
- `<a href="https://...">`
- `chrome.tabs.create({ url })`
- `location.href = "https://..."`
- Comentarios o strings de documentación

Esto evita falsos positivos como “síguenos en Instagram” o links a Discord/GitHub en popup.

### Clasificación de dominios

El backend clasifica dominios en:

- `propio_extension`
- `infraestructura_tecnica`
- `sensible_redes_sociales`
- `sensible_financiero`
- `sensible_identidad`
- `sensible_correo_productividad`
- `sensible_gubernamental`
- `sensible_llm`
- `sensible_data_broker`
- `desconocido`

Los dominios propios e infraestructura técnica se bajan o se omiten del reporte de prioridad. Los dominios sensibles y desconocidos se conservan para explicación y revisión.

También se filtran namespaces técnicos como `www.w3.org`, `xml.org` y `schemas.xmlsoap.org` para evitar tratarlos como endpoints.

## Reglas de correlación implementadas

### Críticas o casi críticas

| Regla                                                             | Confianza aproximada |
| ----------------------------------------------------------------- | -------------------- |
| Cookies + sink de red en el mismo archivo                         | 0.96                 |
| Listener de teclado + sink de red en el mismo archivo             | 0.95                 |
| Campo/selector de credenciales + sink de red en el mismo archivo  | 0.96                 |
| Script remoto MV3 + señal de credenciales/cookies                 | 0.94                 |
| Ofuscación en content script + sink de red                        | 0.93                 |
| Flujo sensible + `<all_urls>`                                     | 0.92                 |
| Mensaje sensible desde content script + sink de red en background | 0.90                 |

### Fuertes

| Regla                                          | Confianza aproximada |
| ---------------------------------------------- | -------------------- |
| `<all_urls>` + `webRequest` + sink de red      | 0.88                 |
| Captura de pantalla/página + sink de red       | 0.90                 |
| `nativeMessaging` + sink de red                | 0.87                 |
| `proxy`/`vpnProvider` declarado                | 0.82                 |
| `debugger` + sink de red                       | 0.88                 |
| `clipboardRead` + sink de red en mismo archivo | 0.90                 |
| `history` + sink de red en mismo archivo       | 0.87                 |
| Ofuscación + `webRequest`/DNR                  | 0.86                 |
| `scripting` + URL sospechosa                   | 0.84                 |

### Señales de atención

| Regla                                              | Tratamiento           |
| -------------------------------------------------- | --------------------- |
| `history`/`tabs` + ejecución dinámica              | Alto                  |
| `cookies` declarado sin uso ni sink                | Medio, baja confianza |
| Content script amplio sin UI visible               | Alto                  |
| Storage + ofuscación                               | Alto                  |
| DOM injection en content script + URL sospechosa   | Alto                  |
| Ofuscación + eval                                  | Alto                  |
| Múltiples señales de credenciales                  | Alto                  |
| IP cruda o TLD sospechoso                          | Alto                  |
| `cookies`/`<all_urls>` + dominio sospechoso + sink | Crítico/fuerte        |

## Manifest avanzado implementado

### `declarativeNetRequest`

El backend lee archivos declarados en `declarative_net_request.rule_resources` y reporta:

- Reglas `redirect` hacia dominios desconocidos o sensibles.
- Redirecciones desde dominios sensibles.
- Reglas amplias de `redirect` o `modifyHeaders` sobre recursos importantes (`main_frame`, `sub_frame`, `xmlhttprequest`, `script`).
- Archivos de reglas que no se pueden parsear.

### `externally_connectable`

Reporta riesgo cuando:

- Acepta orígenes amplios o comodines.
- El código registra `chrome.runtime.onMessageExternal`.

No valida todavía schemas de mensajes ni todas las ramas de `sender.origin`; solo detecta exposición y handlers.

### `web_accessible_resources`

Reporta riesgo cuando:

- Expone recursos ejecutables (`.js`, `.mjs`, `.html`) a matches amplios como `<all_urls>` o `*://*/*`.

## Falsos positivos que el backend reduce

| Caso                                          | Tratamiento                                                       |
| --------------------------------------------- | ----------------------------------------------------------------- |
| Link a Instagram/Discord/GitHub en popup      | No se marca como dominio contactado.                              |
| `window.open`/`chrome.tabs.create`            | Se trata como navegación, no como exfiltración.                   |
| `innerHTML` en popup/options sin sink         | Se descarta como render de UI.                                    |
| Listener de teclado en popup/options sin sink | Se descarta como UX/atajo.                                        |
| `chrome.storage` en UI sin sink               | Se descarta como estado local.                                    |
| Permiso sensible aislado                      | Baja confianza; sirve como contexto, no como positivo confirmado. |
| Namespaces SVG/XML                            | Se filtran como técnicos.                                         |

## Criterio de positivo estático

En el reporte, un hallazgo estático se marca como `positivo` cuando su `confidence` es al menos `0.70`. Hallazgos bajo ese umbral se conservan en `estructura.resultado1` como `falso_positivo`, para que el frontend pueda inspeccionarlos sin mostrarlos como narrativa principal.

## Limitaciones conscientes

Estas limitaciones no aparecen como reglas prometidas:

- No hay reconstrucción completa de payloads interarchivo campo por campo.
- No se valida de forma profunda el schema de mensajes externos.
- No se comparan hashes de librerías conocidas contra versiones oficiales.
- No hay detección avanzada de evasión de sandbox/headless.
- No hay clasificación semántica perfecta de telemetría legítima; se decide por fuentes, sinks, dominio, rol y confianza.

Estas limitaciones son deliberadas para mantener el análisis determinista, rápido y explicable.
