-- ═══════════════════════════════════════════════════════════════════════════════
-- Ext-Sandbox — Database Initialization Script
--
-- Ejecutado automáticamente por PostgreSQL al crear el contenedor (Docker Compose).
-- TypeORM (synchronize: true) crea las tablas de entidades (analysis_jobs,
-- platform_states). Este script gestiona:
--   1. Extensiones PostgreSQL necesarias
--   2. La tabla threat_intel_cache (gestionada por RetentionService, fuera del ORM)
--   3. Índices adicionales de rendimiento
-- ═══════════════════════════════════════════════════════════════════════════════

-- Extensión para generación de UUIDs
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ─── Tabla: threat_intel_cache ────────────────────────────────────────────────
-- Caché de resultados de Threat Intelligence (VirusTotal, URLScan, AbuseIPDB).
-- No es una entidad TypeORM — se purga vía RetentionService.purgeThreatIntelCache().
CREATE TABLE IF NOT EXISTS threat_intel_cache (
    id           UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    domain       VARCHAR(255) NOT NULL,
    provider     VARCHAR(50)  NOT NULL,
    is_malicious BOOLEAN      NOT NULL DEFAULT FALSE,
    score        FLOAT,
    categories   JSONB,
    details      JSONB,
    queried_at   TIMESTAMP    NOT NULL DEFAULT NOW(),
    expires_at   TIMESTAMP    NOT NULL,
    CONSTRAINT uq_threat_intel_domain_provider UNIQUE (domain, provider)
);

CREATE INDEX IF NOT EXISTS idx_threat_intel_domain     ON threat_intel_cache (domain);
CREATE INDEX IF NOT EXISTS idx_threat_intel_expires_at ON threat_intel_cache (expires_at);

-- ─── Nota sobre otras tablas ─────────────────────────────────────────────────
-- Las tablas analysis_jobs y platform_states son creadas automáticamente por
-- TypeORM (synchronize: true en configuración de desarrollo).
-- Los índices adicionales abajo se crean de forma idempotente para producción.

-- Índices de rendimiento para analysis_jobs (se crean tras TypeORM init)
-- Se usan DO $$ para ignorar el error si la tabla no existe aún en el primer boot.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'analysis_jobs') THEN
        CREATE INDEX IF NOT EXISTS idx_analysis_jobs_status
            ON analysis_jobs (status)
            WHERE status NOT IN ('completed', 'failed');

        CREATE INDEX IF NOT EXISTS idx_analysis_jobs_extension_id
            ON analysis_jobs (extension_id);

        CREATE INDEX IF NOT EXISTS idx_analysis_jobs_created_at
            ON analysis_jobs (created_at DESC);
    END IF;
END $$;
