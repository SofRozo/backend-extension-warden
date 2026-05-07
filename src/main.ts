import { NestFactory } from '@nestjs/core';
import { ValidationPipe } from '@nestjs/common';
import { AppModule } from './app.module.js';
import { StructuredLogger } from './common/logger/logger.service.js';

async function bootstrap() {
  const logger = new StructuredLogger();
  const app = await NestFactory.create(AppModule, { logger });

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    }),
  );

  app.enableCors();

  const port = process.env.PORT ?? 3000;
  await app.listen(port);
  logger.log(`Ext-Sandbox API running on port ${port}`, 'Bootstrap');
}
bootstrap();
