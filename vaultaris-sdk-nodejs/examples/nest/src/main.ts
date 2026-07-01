import { NestFactory } from '@nestjs/core';

import { AppModule } from './app.module.js';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  await app.listen(3000);
  console.log('Listening on http://localhost:3000');
  console.log('  GET    /orders/me  — any valid token');
  console.log('  GET    /orders     — token + orders:read');
  console.log('  DELETE /orders/:id — token + orders:delete');
}
bootstrap();
