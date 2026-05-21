import { describe, expect, it } from 'vitest';

import { DpopKey } from '../src/dpop.js';
import {
  IndexedDbKeyStore,
  MemoryKeyStore,
  loadOrCreateDpopKey,
} from '../src/key-store.js';

describe('IndexedDbKeyStore', () => {
  it('round-trips a CryptoKeyPair across separate handles', async () => {
    const store = new IndexedDbKeyStore({ dbName: `vault-test-${crypto.randomUUID()}` });

    expect(await store.load()).toBeNull();

    const pair = (await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['sign', 'verify'],
    )) as CryptoKeyPair;
    await store.save(pair);

    const loaded = await store.load();
    expect(loaded).not.toBeNull();
    // The private key must remain non-extractable after a round-trip —
    // this is the property that makes the persistent storage safe.
    expect(loaded!.privateKey.extractable).toBe(false);
    expect(loaded!.privateKey.algorithm.name).toBe('ECDSA');
  });

  it('clear() drops the stored pair', async () => {
    const store = new IndexedDbKeyStore({ dbName: `vault-test-${crypto.randomUUID()}` });

    const pair = (await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['sign', 'verify'],
    )) as CryptoKeyPair;
    await store.save(pair);
    await store.clear();

    expect(await store.load()).toBeNull();
  });
});

describe('loadOrCreateDpopKey', () => {
  it('returns the same jkt across calls (persistence works)', async () => {
    const store = new IndexedDbKeyStore({ dbName: `vault-test-${crypto.randomUUID()}` });

    const first = await loadOrCreateDpopKey(store);
    const second = await loadOrCreateDpopKey(store);

    expect(second.jkt).toBe(first.jkt);
    expect(second.publicJwk).toEqual(first.publicJwk);
  });

  it('with MemoryKeyStore, two stores produce different keys', async () => {
    const a = await loadOrCreateDpopKey(new MemoryKeyStore());
    const b = await loadOrCreateDpopKey(new MemoryKeyStore());
    expect(a.jkt).not.toBe(b.jkt);
  });

  it('round-tripped key still signs correctly', async () => {
    const store = new IndexedDbKeyStore({ dbName: `vault-test-${crypto.randomUUID()}` });
    const first = await loadOrCreateDpopKey(store);
    const second = await loadOrCreateDpopKey(store);

    const msg = new TextEncoder().encode('hello');
    const sig = await second.sign(msg);
    const ok = await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      first.publicKey,
      sig,
      msg,
    );
    expect(ok).toBe(true);
  });
});

describe('DpopKey.fromCryptoKeyPair', () => {
  it('rejects a non-EC public key', async () => {
    const pair = (await crypto.subtle.generateKey(
      { name: 'RSA-PSS', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
      true,
      ['sign', 'verify'],
    )) as CryptoKeyPair;

    await expect(DpopKey.fromCryptoKeyPair(pair)).rejects.toThrow(/EC P-256/);
  });
});
