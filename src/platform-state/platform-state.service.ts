import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Cron, CronExpression } from '@nestjs/schedule';
import { PlatformState } from '../analysis/entities/platform-state.entity.js';
import { EncryptionService } from '../common/crypto/encryption.service.js';
import { StructuredLogger } from '../common/logger/logger.service.js';
import { PlatformLevel } from '../common/enums/risk-level.enum.js';

/**
 * §9.1 — Gestión de cuentas cebo (honeypots) y renovación de sesiones.
 *
 * Responsabilidades:
 *  1. CRUD de plataformas y niveles de acceso.
 *  2. Cron semanal para intentar renovar sesiones de Nivel 2 (cuentas cebo).
 *  3. Degradación automática Nivel 2 → Nivel 3 si la renovación falla.
 *  4. Alerta al operador cuando una cuenta debe ser restaurada manualmente.
 */
@Injectable()
export class PlatformStateService {
  constructor(
    @InjectRepository(PlatformState)
    private readonly platformRepo: Repository<PlatformState>,
    private readonly encryption: EncryptionService,
    private readonly logger: StructuredLogger,
  ) {}

  // ─── Consultas ─────────────────────────────────────────────────────────────

  async findAll(): Promise<PlatformState[]> {
    return this.platformRepo.find({ order: { level: 'ASC', domain: 'ASC' } });
  }

  async findByDomain(domain: string): Promise<PlatformState | null> {
    return this.platformRepo.findOne({ where: { domain } });
  }

  async findByLevel(level: PlatformLevel): Promise<PlatformState[]> {
    return this.platformRepo.find({ where: { level, isActive: true } });
  }

  // ─── Actualización de nivel ────────────────────────────────────────────────

  /**
   * Degrada manualmente una plataforma de Nivel 2 → Nivel 3.
   * Se usa cuando la cuenta cebo es bloqueada irrecuperablemente.
   */
  async demoteTolevel3(domain: string, reason: string): Promise<void> {
    const platform = await this.findByDomain(domain);
    if (!platform) {
      this.logger.warn(
        `Cannot demote unknown platform: ${domain}`,
        'PlatformStateService',
      );
      return;
    }

    if (platform.level !== PlatformLevel.LEVEL_2_HONEYPOT) {
      return; // Nothing to demote
    }

    await this.platformRepo.update(
      { domain },
      { level: PlatformLevel.LEVEL_3_RESTRICTED },
    );

    this.logger.warn(
      `§9.1 PLATFORM DEMOTED: ${domain} → Level 3 (restricted). Reason: ${reason}. ` +
        'Manual intervention required to restore honeypot account and re-promote.',
      'PlatformStateService',
    );
  }

  /**
   * Promueve una plataforma de vuelta a Nivel 2 cuando la cuenta cebo
   * ha sido restaurada manualmente por el operador.
   */
  async promoteToLevel2(
    domain: string,
    storageStatePath: string,
  ): Promise<void> {
    await this.platformRepo.update(
      { domain },
      {
        level: PlatformLevel.LEVEL_2_HONEYPOT,
        storageStatePath,
        lastRenewal: new Date(),
      },
    );

    this.logger.log(
      `§9.1 Platform promoted to Level 2: ${domain} (storageState: ${storageStatePath})`,
      'PlatformStateService',
    );
  }

  // ─── Cron: renovación semanal de sesiones ──────────────────────────────────

  /**
   * §9.1 — Cron semanal: intenta verificar que los storageState de cuentas cebo
   * siguen siendo válidos. Si un archivo está ausente o corrupto, degrada
   * la plataforma a Nivel 3 y genera alerta para el operador.
   *
   * Nota: La renovación real de tokens requiere interacción manual (2FA, CAPTCHA).
   * Este cron solo verifica integridad de los archivos cifrados existentes.
   * Si la sesión realmente expiró, la plataforma pasa a Nivel 3 hasta que
   * el operador renueve el storageState manualmente.
   */
  @Cron(CronExpression.EVERY_WEEK)
  async renewHoneypotSessions(): Promise<void> {
    this.logger.log(
      '§9.1 Starting weekly honeypot session integrity check',
      'PlatformStateService',
    );

    const level2Platforms = await this.findByLevel(PlatformLevel.LEVEL_2_HONEYPOT);

    if (level2Platforms.length === 0) {
      this.logger.log(
        '§9.1 No Level 2 platforms to check',
        'PlatformStateService',
      );
      return;
    }

    for (const platform of level2Platforms) {
      await this.checkAndRenewPlatform(platform);
    }
  }

  private async checkAndRenewPlatform(platform: PlatformState): Promise<void> {
    const { domain, storageStatePath } = platform;

    if (!storageStatePath) {
      this.emitAdminAlert(
        domain,
        'No storageState path configured for Level 2 platform',
      );
      await this.demoteTolevel3(domain, 'Missing storageState path');
      return;
    }

    try {
      // Verify the encrypted storageState file is accessible and decryptable
      const stateData = this.encryption.loadAndDecryptState(storageStatePath);

      // Validate minimal structure: must have cookies array
      if (
        !stateData ||
        typeof stateData !== 'object' ||
        !('cookies' in stateData)
      ) {
        throw new Error('Invalid storageState structure — missing cookies');
      }

      const cookies = (stateData as { cookies: any[] }).cookies;
      if (!Array.isArray(cookies) || cookies.length === 0) {
        throw new Error('Empty cookies array — session likely expired');
      }

      // Check if session cookies are still within their expiry window
      const now = Date.now() / 1000; // Unix timestamp in seconds
      const sessionCookies = cookies.filter(
        (c: any) => c.session || (c.expires && c.expires > now),
      );

      if (sessionCookies.length === 0) {
        throw new Error('All session cookies are expired');
      }

      // Update lastRenewal timestamp
      await this.platformRepo.update(
        { domain },
        { lastRenewal: new Date() },
      );

      this.logger.log(
        `§9.1 Honeypot session OK for ${domain} (${cookies.length} cookies, ${sessionCookies.length} active)`,
        'PlatformStateService',
      );
    } catch (err) {
      const reason = err instanceof Error ? err.message : String(err);

      this.emitAdminAlert(domain, reason);
      await this.demoteTolevel3(domain, reason);
    }
  }

  /**
   * Emite una alerta para que el operador intervenga manualmente.
   * En producción esto debería enviar un email/Slack/PagerDuty.
   * Por ahora registra un log de nivel ERROR con tag ADMIN_ACTION_REQUIRED.
   */
  private emitAdminAlert(domain: string, reason: string): void {
    this.logger.error(
      `[ADMIN_ACTION_REQUIRED] §9.1 Honeypot account EXPIRED/BROKEN for ${domain}. ` +
        `Reason: ${reason}. ` +
        'Platform demoted to Level 3. Manual steps: (1) Re-create/restore the account, ' +
        '(2) Export new storageState via Playwright, (3) Encrypt and store with EncryptionService, ' +
        '(4) Call PlatformStateService.promoteToLevel2() to re-enable.',
      undefined,
      'PlatformStateService',
    );
  }

  // ─── Registro de nueva plataforma ─────────────────────────────────────────

  async upsertPlatform(data: {
    domain: string;
    platformName: string;
    level: PlatformLevel;
    category?: string;
    loginUrl?: string;
    storageStatePath?: string;
  }): Promise<PlatformState> {
    const existing = await this.findByDomain(data.domain);

    if (existing) {
      await this.platformRepo.update({ domain: data.domain }, {
        platformName: data.platformName,
        level: data.level,
        category: data.category,
        loginUrl: data.loginUrl,
        storageStatePath: data.storageStatePath ?? existing.storageStatePath,
        isActive: true,
      });
      return (await this.findByDomain(data.domain))!;
    }

    const platform = this.platformRepo.create({
      ...data,
      isActive: true,
    });
    return this.platformRepo.save(platform);
  }
}
