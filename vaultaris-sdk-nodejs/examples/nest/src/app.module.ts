import { Module } from '@nestjs/common';

import { OrdersController } from './orders.controller.js';
import { VaultarisModule } from './vaultaris.module.js';

@Module({
  imports: [
    VaultarisModule.forRoot({
      baseUrl: process.env.VAULTARIS_URL ?? 'http://localhost:8080',
      apiKey: process.env.VAULTARIS_API_KEY ?? '',
    }),
  ],
  controllers: [OrdersController],
})
export class AppModule {}
