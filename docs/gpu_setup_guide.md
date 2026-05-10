# Guía de Instalación en Servidor con GPU (Lab de la U)

Para ejecutar el pipeline de Ext-Sandbox con máximo rendimiento, sigue estos pasos en el computador con GPU.

## 1. Requisitos de Hardware
- **GPU:** NVIDIA (RTX 3060 o superior recomendada) con al menos 8GB de VRAM.
- **RAM:** 16GB+ (32GB ideal).
- **Almacenamiento:** 20GB libres para modelos.

## 2. Requisitos de Software
Instala las siguientes herramientas en orden:
1. **Ollama:** [ollama.com](https://ollama.com) (Asegúrate de que detecte la GPU al iniciar).
2. **Node.js:** Versión 22 o superior.
3. **Docker Desktop:** Para correr Redis y la base de datos.
4. **Git:** Para clonar el repositorio.

## 3. Preparación de Modelos
Ejecuta estos comandos en una terminal para tener los modelos listos:
```powershell
ollama pull llama3.2:3b    # Para navegación rápida (Stagehand/Agent 4)
ollama pull qwen3.5:4b     # Para análisis de intención y SAST (Equilibrio)
ollama pull qwen3.5:9b     # Para reportes finales de alta calidad (Si hay 12GB+ VRAM)
```

## 4. Configuración del Proyecto
1. Clona el repositorio: `git clone <tu-repo>`
2. Entra a la carpeta: `cd ext-sandbox`
3. Instala dependencias: `npm install`
4. Copia el archivo `.env.example` a `.env` y ajusta:
   - `OLLAMA_HOST=http://127.0.0.1:11434`
   - `MODELO_OLLAMA=llama3.2:3b`
   - `USAR_OLLAMA=true`

## 5. Ejecución del Pipeline
1. Levanta los servicios base: `docker-compose up -d redis db`
2. Compila el proyecto: `npm run build` (o usa el comando tsc directo).
3. Inicia el Worker:
   ```powershell
   $env:DEMO_MODE="true"
   $env:WORKER_QUEUE="analysis-demo"
   node dist/src/main-worker.js
   ```

## 6. Verificación de GPU
Para confirmar que Ollama está usando la GPU mientras corre el análisis:
1. Abre el **Administrador de Tareas** de Windows.
2. Ve a la pestaña **Rendimiento**.
3. Selecciona **GPU**. Deberías ver picos en "Dedicated GPU Memory" y "GPU Compute" cuando los agentes estén trabajando.
