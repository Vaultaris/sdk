export {
  DpopKey,
  signProof,
  thumbprint,
  type DpopSigner,
  type DpopPublicJwk,
} from './dpop.js';

export {
  IndexedDbKeyStore,
  MemoryKeyStore,
  loadOrCreateDpopKey,
  type DpopKeyStore,
} from './key-store.js';

export {
  VaultarisClient,
  VaultarisError,
  type ApiKey,
  type ApiKeyWithSecret,
  type AuditLog,
  type AuthScheme,
  type AuthenticationStats,
  type BatchPermissionCheck,
  type BatchPermissionResult,
  type CreateApiKeyInput,
  type Group,
  type Page,
  type Pagination,
  type Permission,
  type PermissionCheck,
  type PermissionToCheck,
  type Role,
  type StatsQuery,
  type Tenant,
  type TenantOverview,
  type TokenResponse,
  type TokenValidation,
  type User,
  type UserInfo,
  type VaultarisConfig,
} from './client.js';

export {
  computeFingerprint,
  collectComponents,
  type FingerprintComponents,
} from './fingerprint.js';
