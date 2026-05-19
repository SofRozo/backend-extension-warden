# Pruebas de detección — Extension Warden

Script de pruebas automatizadas para el trabajo de grado. Envía extensiones `.crx` al backend, espera los resultados y genera un informe en **Excel** organizado por batches, más el JSON completo de cada job.

---

## Estructura

```
tests/
├── test_malicious_extensions.mjs   ← script principal
├── resultados/                     ← archivos generados (uno por ejecución)
│   └── <timestamp>/
│       ├── batch-01/
│       │   ├── <jobId>-<nombre>.json   ← reporte completo por extensión
│       │   └── resultados-batch-01.xlsx
│       └── batch-02/
│           └── ...
└── README.md
```

---

## Requisitos previos

| Requisito | Versión mínima | Verificar |
|-----------|---------------|-----------|
| Node.js | 18+ | `node --version` |
| Backend corriendo | — | `http://localhost:3000/health/ready` debe responder `200` |
| PostgreSQL + Redis activos | — | requeridos por el backend |
| `exceljs` instalado | — | ya incluido en `package.json` del backend |

---

## Cómo ejecutar

Desde la carpeta `backend-extension-warden/tests/`:

```powershell
# 50 extensiones en batches de 10 (configuración por defecto)
node test_malicious_extensions.mjs

# Prueba rápida: 5 extensiones, batch de 5
node test_malicious_extensions.mjs --count 5 --batch 5

# 100 extensiones en batches de 25
node test_malicious_extensions.mjs --count 100 --batch 25

# Backend en otro puerto
node test_malicious_extensions.mjs --url http://localhost:3001
```

### Parámetros

| Parámetro | Por defecto | Descripción |
|-----------|-------------|-------------|
| `--url` | `http://localhost:3000` | URL base del backend |
| `--dir` | `../../Malicious Browser Extensions` | Carpeta con los `.crx` a analizar |
| `--out` | `./resultados/<timestamp>` | Carpeta raíz donde se guardan los resultados |
| `--count` | `50` | Total de extensiones a procesar |
| `--batch` | `10` | Extensiones por batch (genera un Excel al completar cada uno) |
| `--delay` | `2` | Segundos de pausa entre envíos (respeta el rate-limit: 5 req/10s) |

---

## Flujo del script

```
Verifica backend (GET /health/ready)
    │
    └─ Para cada .crx (en orden alfabético):
           │
           ├─ POST /analyze/upload          → jobId
           ├─ GET  /status/:jobId           → polling cada 10s (máx 22 min)
           └─ GET  /report/:jobId           → reporte completo
                  │
                  ├─ Guarda <jobId>-<nombre>.json  en la carpeta del batch
                  └─ Acumula fila con métricas para el Excel

    Al completar cada batch (o al terminar):
           ├─ Imprime resumen en consola
           └─ Genera resultados-batch-NN.xlsx
```

El script procesa las extensiones **secuencialmente** — si se interrumpe, los JSON y Excel de los batches completados quedan guardados.

---

## Archivos generados

### JSON por extensión

Archivo: `<jobId>-<nombre_crx>.json`

Contiene el reporte completo devuelto por el backend, con toda la estructura de `agente1`, `resumen_usuario`, `estructura`, `permisos_no_usados`, etc. Útil para inspección manual o análisis posterior.

### Excel por batch

Archivo: `resultados-batch-NN.xlsx` con dos hojas:

#### Hoja "Resultados" — una fila por extensión

| Grupo | Columnas |
|-------|---------|
| Identificación | `#`, `archivo`, `job_id`, `estado_job` |
| Agente IA | `veredicto_agente`, `nivel_riesgo_agente`, `categoria_agente`, `proposito`, `explicacion` |
| Veredicto usuario | `veredicto_usuario`, `nivel_usuario`, `resumen_usuario`, `razones_usuario` |
| Preguntas frecuentes (10) | `faq_puede_capturar_contrasenas`, `faq_puede_registrar_teclas`, `faq_puede_espiar_sin_saberlo`, `faq_puede_leer_formularios`, `faq_puede_modificar_paginas`, `faq_puede_interceptar_trafico`, `faq_puede_ver_paginas_visitadas`, `faq_puede_ver_historial`, `faq_codigo_oculto_o_sospechoso`, `faq_puede_afectar_otras_extensiones` |
| Categorías de comportamiento (13) | `cat_acceso_general`, `cat_modificacion_paginas`, `cat_lectura_informacion`, `cat_captura_credenciales`, `cat_keylogging`, `cat_seguimiento_privacidad`, `cat_manipulacion_trafico`, `cat_acceso_historial`, `cat_descargas_archivos`, `cat_abuso_management`, `cat_mineria_recursos`, `cat_fingerprinting_severo`, `cat_ofuscacion_transparencia` |
| Puntuación de riesgo local | `risk_score`, `risk_level` — calculados desde `report.puntuacion_riesgo` (motor local de permisos) |
| Hallazgos estáticos | `hallazgos_positivos_total`, `hallazgos_criticos`, `hallazgos_altos`, `hallazgos_medios`, `hallazgos_bajos` |
| Dominios | `dominios_prioritarios`, `dominios_desconocidos`, `dominios_sensibles_lista` |
| Permisos no usados | `permisos_no_usados_total`, `permisos_no_usados_criticos`, `permisos_no_usados_lista` |
| Tiempo | `duracion_analisis_s`, `error` |

**Colores en la hoja:**
- `veredicto_agente` y `veredicto_usuario`: rojo (maliciosa), amarillo (sospechosa), verde (benigna)
- Columnas `cat_*`: rojo (critico), naranja (sospechoso), azul claro (capacidad), gris (no_detectado)
- Columnas `faq_*`: rojo (si), amarillo (posible)

Los valores de las columnas FAQ son: `si` / `posible` / `no_detectado`.
Los valores de las columnas `cat_*` son: `critico` / `sospechoso` / `capacidad` / `no_detectado`.

#### Hoja "Resumen" — métricas consolidadas del batch

Incluye para copiar al documento de grado:
- Totales: completadas, fallidas, duración promedio
- Distribución de veredictos del agente IA (maliciosa / sospechosa / benigna)
- Distribución de veredictos de usuario
- Distribución de niveles de riesgo (crítico / alto / medio / bajo)
- Las 13 categorías con conteo por estado (critico / sospechoso / capacidad)
- Las 10 preguntas FAQ con conteo de `si` y `posible`
- Totales de hallazgos estáticos por severidad
- Permisos declarados pero no usados
- Dominios sensibles y desconocidos

---

## Métricas para el documento de grado

**Tasa de Detección (True Positive Rate)**
```
TPR = extensiones con veredicto_agente = "maliciosa" / total completadas × 100
```

**Tiempo promedio de análisis**
```
Promedio de la columna duracion_analisis_s (ya en segundos)
```

**Distribución de categorías de comportamiento**
```
Contar filas cat_X = "critico" → identifica qué técnicas son más frecuentes
```
