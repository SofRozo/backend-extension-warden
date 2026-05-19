# API Reference

Base URL local: `http://localhost:3000`

Rate limiting: 5 req/10s por IP (burst), 20 req/60s (sustained).

---

## POST /analyze

Encola el análisis de una extensión del Chrome Web Store.

**Request**
```json
{ "extensionId": "cjpalhdlnbpafiamejdnhcphjbkeiagm" }
```

El `extensionId` debe tener exactamente 32 caracteres alfanuméricos en minúsculas.

**Response 202**
```json
{ "jobId": "550e8400-e29b-41d4-a716-446655440000", "status": "queued" }
```

**Response 400** — ID inválido o body malformado.

---

## POST /analyze/upload

Analiza un archivo `.crx` o `.zip` subido directamente.

**Request**: `multipart/form-data` con campo `file`.

**Response 202**: igual que `/analyze`.

---

## GET /status/:jobId

Devuelve el estado actual del análisis.

**Response 200**
```json
{
  "jobId": "550e8400-...",
  "extensionId": "cjpalhdlnbpafiamejdnhcphjbkeiagm",
  "status": "preprocessing",
  "createdAt": "2026-05-18T20:00:00Z",
  "updatedAt": "2026-05-18T20:00:15Z",
  "errorMessage": null
}
```

Posibles valores de `status`: `queued` | `downloading` | `preprocessing` | `ai_analysis` | `generating_report` | `completed` | `failed`

---

## GET /report/:jobId

Devuelve el reporte completo. Solo disponible si `status === "completed"`.

**Response 200** (estructura simplificada)
```json
{
  "jobId": "550e8400-...",
  "extensionId": "cjpalhdlnbpafiamejdnhcphjbkeiagm",
  "crxHash": "220a0a72...",
  "cwsCategory": "VPN & Proxy",
  "agente1": {
    "veredicto": "maliciosa",
    "riesgo": "critico",
    "proposito": "Extensión de VPN que redirige el tráfico…",
    "parrafo": "La extensión Urban VPN…",
    "recomendacion": "Desinstala esta extensión…",
    "respuestas": {
      "puede_leer_formularios": { "valor": "posible", "razon": "…" },
      "puede_ver_paginas_visitadas": { "valor": "si", "razon": "…" },
      "puede_capturar_contrasenas": { "valor": "posible", "razon": "…" },
      "puede_modificar_paginas": { "valor": "no_detectado", "razon": "…" },
      "puede_espiar_sin_saberlo": { "valor": "si", "razon": "…" },
      "puede_ver_historial": { "valor": "si", "razon": "…" },
      "puede_registrar_teclas": { "valor": "no_detectado", "razon": "…" },
      "puede_interceptar_trafico": { "valor": "si", "razon": "…" },
      "codigo_oculto_o_sospechoso": { "valor": "si", "razon": "…" },
      "puede_afectar_otras_extensiones": { "valor": "si", "razon": "…" }
    },
    "ranSuccessfully": true
  },
  "hallazgos_estaticos_positivos": [
    {
      "tipo": "flujo_datos_a_red",
      "filePath": "service-worker/index.js",
      "line": 23829,
      "detail": "fetch → external host",
      "severity": "high",
      "codeSnippet": "fetch('https://…')"
    }
  ],
  "estructura": {
    "resultado1": [ /* hallazgos estáticos completos */ ],
    "resultado2_priority": [ /* dominios sensibles */ ],
    "resultado2_unknown": [ /* dominios desconocidos */ ],
    "resumen_usuario": [
      {
        "id": "manipulacion_trafico",
        "titulo": "Manipulación de tráfico",
        "estado": "critico",
        "resumen": "La extensión intercepta todo el tráfico…",
        "evidencias": ["Permiso proxy declarado…", "webRequest detectado…"],
        "reglas_activadas": ["traffic.proxy_permission", "traffic.web_request"],
        "preguntas_responde": ["puede_interceptar_trafico"],
        "hallazgos_codigo": ["service-worker/index.js:1"]
      }
    ],
    "permisos_no_usados": [
      {
        "permission": "webRequestAuthProvider",
        "severity": "alto",
        "message": "Permiso "webRequestAuthProvider" declarado pero no detectado en código"
      }
    ]
  }
}
```

---

## GET /health

Liveness probe. Responde `200` si el proceso está vivo.

```json
{ "status": "ok", "timestamp": "2026-05-18T20:00:00Z" }
```

## GET /health/ready

Readiness probe. Responde `200` si PostgreSQL y Redis responden, `503` si no.

```json
{
  "status": "ok",
  "checks": { "database": "ok", "redis": "ok" }
}
```
