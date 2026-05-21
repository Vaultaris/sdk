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
  type VaultarisConfig,
  type TokenValidation,
  type PermissionCheck,
  type UserInfo,
} from './client.js';

export {
  computeFingerprint,
  collectComponents,
  type FingerprintComponents,
} from './fingerprint.js';
