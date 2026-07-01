/**
 * Orders controller — applies `VaultarisAuthGuard` once at the class
 * level so every route requires a valid token, then layers
 * `@RequirePermission(...)` on individual routes for fine-grained checks.
 */

import {
  Controller,
  Delete,
  Get,
  Param,
  Req,
  UseGuards,
} from '@nestjs/common';

import {
  RequirePermission,
  VaultarisAuthGuard,
} from './vaultaris.module.js';

interface AuthedRequest extends Request {
  user: {
    tenantId: string;
    userId: string;
    username?: string;
    roles: string[];
  };
}

@Controller('orders')
@UseGuards(VaultarisAuthGuard)
export class OrdersController {
  /** Any valid token. */
  @Get('me')
  me(@Req() req: AuthedRequest) {
    return { user: req.user };
  }

  /** Requires `orders:read`. */
  @Get()
  @RequirePermission('orders', 'read')
  list(@Req() req: AuthedRequest) {
    return {
      orders: ['ORD-001', 'ORD-002'],
      servedTo: req.user.username,
    };
  }

  /** Requires `orders:delete`. */
  @Delete(':id')
  @RequirePermission('orders', 'delete')
  remove(@Param('id') id: string, @Req() req: AuthedRequest) {
    return {
      deletedId: id,
      deletedBy: req.user.username,
      userId: req.user.userId,
    };
  }
}
