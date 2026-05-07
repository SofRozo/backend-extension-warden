import { Injectable } from '@nestjs/common';
import { Stagehand } from '@browserbasehq/stagehand';
import { z } from 'zod';
import { LlmClientService } from '../../agents/llm/llm-client.service.js';
import { StructuredLogger } from '../../common/logger/logger.service.js';
import type { DomainCategory } from '../../agents/interfaces/agents.interfaces.js';
import type { SandboxDomainObservation } from '../../common/interfaces/analysis.interfaces.js';

/**
 * Implementation of Agent 4 using the official Stagehand library.
 */
@Injectable()
export class StagehandService {
  constructor(
    private readonly llm: LlmClientService,
    private readonly logger: StructuredLogger,
  ) {}

  async navigateDomain(
    page: any,
    domain: string,
    category: DomainCategory,
    proposito: string,
    jobId: string,
  ): Promise<SandboxDomainObservation> {
    this.logger.logWithJob(jobId, 'info', `Stagehand — starting analysis of ${domain}`, 'StagehandService');

    const url = `https://${domain}`;
    const observations: string[] = [];
    const actionsPerformed: string[] = [];

    try {
      const stagehand = new Stagehand({
        env: 'LOCAL',
        apiKey: 'not-needed-for-local',
      }) as any;

      await stagehand.init();
      // Use the provided page
      stagehand.page = page;

      // Step 1: Observe the landing page
      this.logger.logWithJob(jobId, 'info', 'Stagehand — observing landing page', 'StagehandService');
      const observation = await stagehand.observe(
        `Identifica elementos de login o formularios sensibles en ${domain} relacionados con el propósito: ${proposito}`
      );
      observations.push(`Observación inicial: ${observation.length} elementos de interés encontrados.`);

      // Step 2: Act based on the category
      if (category === 'sensible_financiero' || category === 'sensible_identidad') {
        this.logger.logWithJob(jobId, 'info', 'Stagehand — attempting to find login form', 'StagehandService');
        
        await stagehand.act(
          'Busca el campo de correo electrónico o usuario y escribe "test_extwarden@mailtest.com"'
        );
        actionsPerformed.push('type:honeypot_email');

        await stagehand.act(
          'Busca el campo de contraseña y escribe "ExTw4rd3n_F4ke!"'
        );
        actionsPerformed.push('type:honeypot_password');

        await stagehand.act(
          'Haz clic en el botón de Iniciar Sesión o Continuar'
        );
        actionsPerformed.push('click:submit');
      } else {
        // Generic exploration for other categories
        await stagehand.act(
          'Explora la página principal buscando secciones de configuración o perfil de usuario.'
        );
        actionsPerformed.push('act:exploration');
      }

      const finalSummary = await stagehand.page.extract({
        instruction: '¿La extensión inyectó algún elemento visual o modificó el comportamiento de la página?',
        schema: z.object({
          detectado: z.boolean(),
          descripcion: z.string(),
        })
      });

      if (finalSummary.detectado) {
        observations.push(`Detección de Stagehand: ${finalSummary.descripcion}`);
      }

      return {
        domain,
        url,
        observations,
        actionsPerformed,
        requestsToThisDomain: 0, // Tracked via network interceptor
        domModificationsDetected: !!finalSummary.detectado,
        credentialsSubmitted: category === 'sensible_financiero',
      };

    } catch (err) {
      const msg = `Stagehand failed for ${domain}: ${err instanceof Error ? err.message : String(err)}`;
      this.logger.logWithJob(jobId, 'warn', msg, 'StagehandService');
      return {
        domain,
        url,
        observations: [msg],
        actionsPerformed: [],
        requestsToThisDomain: 0,
        domModificationsDetected: false,
        credentialsSubmitted: false,
        error: msg,
      };
    }
  }
}
