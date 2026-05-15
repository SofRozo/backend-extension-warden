# Pruebas de detección — Extension Warden

Módulo de pruebas automatizadas para el trabajo de grado.
Envía extensiones `.crx` al backend, espera los resultados y genera un informe en **CSV + Excel**.

---

## Estructura

```
tests/
├── test_malicious_extensions.mjs   ← script principal
├── resultados/                     ← aquí se guardan los archivos generados
│   └── resultados_FECHA.csv / .xlsx
└── README.md                       ← este archivo
```

---

## Requisitos previos

| Requisito | Versión mínima | Verificar |
|-----------|---------------|-----------|
| Node.js   | 18            | `node --version` |
| Backend corriendo | — | `http://localhost:3000/health/ready` debe responder `200` |
| PostgreSQL + Redis activos | — | requeridos por el backend |

---

## Instalación de dependencias

El script no necesita paquetes para generar el **CSV**.
Para generar también el **Excel (.xlsx)** ejecuta una sola vez:

```powershell
# Desde la carpeta raíz del proyecto (tesis-mishi/)
npm install exceljs
```

> `exceljs` ya estará disponible si el `package.json` raíz lo incluye.

---

## Cómo ejecutar

Abre una terminal en la carpeta `backend-extension-warden/tests/` y ejecuta:

```powershell
# Prueba completa: 50 extensiones maliciosas (configuración por defecto)
node test_malicious_extensions.mjs

# Prueba rápida: solo 5 extensiones (para verificar que todo funciona)
node test_malicious_extensions.mjs --count 5

# Backend en otro puerto
node test_malicious_extensions.mjs --url http://localhost:3001

# Todos los parámetros disponibles
node test_malicious_extensions.mjs --url http://localhost:3000 --count 50 --delay 2
```

### Parámetros

| Parámetro | Por defecto | Descripción |
|-----------|-------------|-------------|
| `--url`   | `http://localhost:3000` | URL base del backend |
| `--count` | `50` | Número de extensiones a probar |
| `--delay` | `2` | Segundos de pausa entre extensiones (respeta el rate-limit del backend: 5 req/10s) |
| `--dir`   | `../../Malicious Browser Extensions` | Carpeta con los `.crx` |
| `--out`   | `./resultados` | Carpeta donde se guardan los archivos |

---

## Flujo del script

```
Para cada .crx
    │
    ├─ POST /analyze/upload   →  obtiene jobId
    ├─ GET  /status/:jobId    →  polling cada 6s (máx 6 min)
    └─ GET  /report/:jobId    →  reporte completo
           │
           └─ escribe fila en CSV al instante
                     (no se pierde nada si se interrumpe)

Al finalizar:
    ├─ Imprime resumen en consola
    ├─ Guarda resultados/resultados_FECHA.csv
    └─ Guarda resultados/resultados_FECHA.xlsx  (si exceljs está instalado)
```

---

## Archivos generados

Los archivos se guardan en `tests/resultados/` con timestamp en el nombre
para que cada ejecución genere archivos nuevos sin sobreescribir los anteriores.

### Columnas del CSV / Excel

| Columna | Descripción |
|---------|-------------|
| `#` | Número secuencial |
| `filename` | Nombre del archivo `.crx` |
| `extension_id` | ID asignado por el backend |
| `job_id` | UUID del job de análisis |
| `upload_status` | `ok` / `error` |
| `analysis_status` | `completed` / `failed` / `timeout` |
| `overall_risk` | `critical` / `high` / `medium` / `low` / `none` |
| `confidence` | Confianza del modelo (0.0 – 1.0) |
| `detected_malicious` | **SÍ** si riesgo es critical/high/medium, **NO** si es low/none |
| `analysis_duration_ms` | Duración del análisis dentro del backend (ms) |
| `total_elapsed_s` | Tiempo total de pared: upload → reporte (segundos) |
| `privacy_labels_count` | Cantidad de comportamientos maliciosos detectados |
| `privacy_categories` | Ej: `keylogger, data_theft, injection` |
| `privacy_severities` | Severidad de cada label |
| `static_findings_count` | Hallazgos del análisis estático (AST) |
| `contacted_urls_count` | URLs contactadas durante análisis dinámico |
| `malicious_urls_count` | URLs con reputación maliciosa |
| `threat_detections` | Detecciones de VirusTotal / URLScan / AbuseIPDB |
| `recommendation` | Recomendación generada (primeros 250 caracteres) |
| `error` | Mensaje de error si el análisis falló |

### Hojas del Excel

- **Resultados Detallados** — filas coloreadas por nivel de riesgo:
  - Rojo `#FF4C4C` → critical
  - Naranja `#FF9933` → high
  - Amarillo `#FFD966` → medium
  - Verde `#70AD47` → low
  - Gris → failed / timeout
- **Resumen** — métricas consolidadas para copiar al documento de grado:
  - Tasa de detección
  - Distribución por nivel de riesgo
  - Duración promedio del análisis

---

## Métricas para el documento de grado

A partir del archivo generado se pueden calcular:

**Tasa de Detección (True Positive Rate)**
```
TPR = extensiones con detected_malicious = "SÍ" / total completadas × 100
```

**Tiempo promedio de análisis**
```
Promedio de la columna analysis_duration_ms (dividir entre 1000 para segundos)
```

**Distribución de riesgo**
```
Contar filas por overall_risk → gráfica de barras o torta
```
