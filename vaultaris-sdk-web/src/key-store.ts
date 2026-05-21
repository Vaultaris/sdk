/**
 * Persistence backends for the DPoP key.
 *
 * The default [`IndexedDbKeyStore`] is the recommended choice for
 * browsers: IndexedDB is the only persistent storage that can
 * round-trip a non-extractable `CryptoKey` without ever materialising
 * the private bytes in JS. The key is reused across page reloads — and
 * the binding to its access token survives — but never becomes
 * exfiltrable.
 *
 * Applications that need a different lifecycle (in-memory only for an
 * ephemeral session, `chrome.storage` in extension contexts, etc.)
 * implement [`DpopKeyStore`] and pass it explicitly.
 */

import { DpopKey } from './dpop.js';

/**
 * Pluggable persistence for the DPoP keypair. Implementations must
 * round-trip the `CryptoKeyPair` losslessly — the SDK relies on the
 * `privateKey` retaining its `extractable=false` property.
 */
export interface DpopKeyStore {
  /** Return the stored keypair, or `null` if none. */
  load(): Promise<CryptoKeyPair | null>;
  /** Persist `pair` so a subsequent `load()` returns it. */
  save(pair: CryptoKeyPair): Promise<void>;
  /** Drop the stored keypair, if any. */
  clear(): Promise<void>;
}

const DEFAULT_DB = 'vaultaris-dpop';
const DEFAULT_STORE = 'keys';
const DEFAULT_RECORD = 'default';

/**
 * IndexedDB-backed store. Stores the `CryptoKeyPair` directly so the
 * non-extractable private key never has to leave WebCrypto land.
 */
export class IndexedDbKeyStore implements DpopKeyStore {
  private readonly dbName: string;
  private readonly storeName: string;
  private readonly recordKey: string;

  constructor(
    opts: { dbName?: string; storeName?: string; recordKey?: string } = {},
  ) {
    this.dbName = opts.dbName ?? DEFAULT_DB;
    this.storeName = opts.storeName ?? DEFAULT_STORE;
    this.recordKey = opts.recordKey ?? DEFAULT_RECORD;
  }

  async load(): Promise<CryptoKeyPair | null> {
    const db = await this.open();
    try {
      return await new Promise<CryptoKeyPair | null>((resolve, reject) => {
        const tx = db.transaction(this.storeName, 'readonly');
        const req = tx.objectStore(this.storeName).get(this.recordKey);
        req.onsuccess = () => {
          const v = req.result as CryptoKeyPair | undefined;
          resolve(v ?? null);
        };
        req.onerror = () => reject(req.error);
      });
    } finally {
      db.close();
    }
  }

  async save(pair: CryptoKeyPair): Promise<void> {
    const db = await this.open();
    try {
      await new Promise<void>((resolve, reject) => {
        const tx = db.transaction(this.storeName, 'readwrite');
        tx.objectStore(this.storeName).put(pair, this.recordKey);
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
        tx.onabort = () => reject(tx.error);
      });
    } finally {
      db.close();
    }
  }

  async clear(): Promise<void> {
    const db = await this.open();
    try {
      await new Promise<void>((resolve, reject) => {
        const tx = db.transaction(this.storeName, 'readwrite');
        tx.objectStore(this.storeName).delete(this.recordKey);
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
        tx.onabort = () => reject(tx.error);
      });
    } finally {
      db.close();
    }
  }

  private open(): Promise<IDBDatabase> {
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(this.dbName, 1);
      req.onupgradeneeded = () => {
        const db = req.result;
        if (!db.objectStoreNames.contains(this.storeName)) {
          db.createObjectStore(this.storeName);
        }
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }
}

/**
 * Volatile in-memory store. Useful for tests, ephemeral sessions and
 * service workers that don't outlive the page. The keypair is lost the
 * moment the JS context shuts down.
 */
export class MemoryKeyStore implements DpopKeyStore {
  private pair: CryptoKeyPair | null = null;

  async load(): Promise<CryptoKeyPair | null> {
    return this.pair;
  }

  async save(pair: CryptoKeyPair): Promise<void> {
    this.pair = pair;
  }

  async clear(): Promise<void> {
    this.pair = null;
  }
}

/**
 * Load the DPoP key from `store`, generating + persisting a fresh one
 * the first time. Idempotent — call it on every app startup.
 *
 * ```ts
 * const key = await loadOrCreateDpopKey(new IndexedDbKeyStore());
 * ```
 */
export async function loadOrCreateDpopKey(store: DpopKeyStore): Promise<DpopKey> {
  const existing = await store.load();
  if (existing) {
    return DpopKey.fromCryptoKeyPair(existing);
  }

  const pair = (await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign', 'verify'],
  )) as CryptoKeyPair;

  await store.save(pair);
  return DpopKey.fromCryptoKeyPair(pair);
}
