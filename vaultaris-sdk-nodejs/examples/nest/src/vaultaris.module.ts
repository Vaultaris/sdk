/**
 * VaultarisModule — Nest module wrapping `@vaultaris/sdk`.
 *
 * Provides a singleton `VaultarisClient` (injectable via DI) plus the
 * `VaultarisAuthGuard` and `@RequirePermission()` decorator below.
 *
 * Import in your AppModule:
 *
 *   @Module({
 *     imports: [
 *       VaultarisModule.forRoot({
 *         baseUrl: process.env.VAULTARIS_URL!,
 *         apiKey: process.env.VAULTARIS_API_KEY!,
 *       }),
 *     ],
 *   })
 *   export class AppModule {}
 */

import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Inject,
  Injectable,
  Module,
  SetMetadata,
  UnauthorizedException,
  type DynamicModule,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { VaultarisClient } from '@vaultaris/sdk';

export const VAULTARIS_CLIENT = 'VAULTARIS_CLIENT';
const PERMISSION_KEY = 'vaultaris:permission';

export interface VaultarisModuleOptions {
  baseUrl: string;
  apiKey: string;
  timeoutMs?: number;
}

/** Per-handler `@RequirePermission('orders', 'delete')` declaration. */
export const RequirePermission = (resource: string, action: string) =>
  SetMetadata(PERMISSION_KEY, { resource, action });

/**
 * Guard that
 * 1. Validates the incoming Bearer/ApiKey token via Vaultaris.
 * 2. Attaches the resolved principal to `req.user`.
 * 3. If the handler declared `@RequirePermission(r, a)`, enforces it.
 */
@Injectable()
export class VaultarisAuthGuard implements CanActivate {
  constructor(
    @Inject(VAULTARIS_CLIENT) private readonly client: VaultarisClient,
    private readonly reflector: Reflector,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest();
    const auth: string | undefined = req.headers['authorization'];
    const token = auth?.replace(/^(Bearer|ApiKey)\s+/, '');
    if (!token) throw new UnauthorizedException('Missing Authorization header');

    const v = await this.client.validateToken(token);
    if (!v.valid) throw new UnauthorizedException(v.error ?? 'Invalid token');
    if (!v.tenant_id || !v.user_id) {
      throw new UnauthorizedException('Token missing tenant_id or user_id');
    }

    req.user = {
      tenantId: v.tenant_id,
      userId: v.user_id,
      username: v.username,
      roles: v.roles,
    };

    const required = this.reflector.get<{ resource: string; action: string } | undefined>(
      PERMISSION_KEY,
      context.getHandler(),
    );
    if (required) {
      const allowed = await this.client.checkPermission(
        v.tenant_id,
        v.user_id,
        required.resource,
        required.action,
      );
      if (!allowed.allowed) {
        throw new ForbiddenException(
          `Missing permission ${required.resource}:${required.action}`,
        );
      }
    }

    return true;
  }
}

@Module({})
export class VaultarisModule {
  static forRoot(options: VaultarisModuleOptions): DynamicModule {
    return {
      module: VaultarisModule,
      global: true,
      providers: [
        {
          provide: VAULTARIS_CLIENT,
          useFactory: () =>
            new VaultarisClient({
              baseUrl: options.baseUrl,
              apiKey: options.apiKey,
              timeoutMs: options.timeoutMs ?? 30_000,
            }),
        },
        VaultarisAuthGuard,
      ],
      exports: [VAULTARIS_CLIENT, VaultarisAuthGuard],
    };
  }
}
