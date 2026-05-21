/**
 * Base64url-no-pad encoding helpers. Browsers don't ship a native one, so we
 * roll a small ASCII-only implementation. All input must already be bytes;
 * for strings, encode with `TextEncoder` first.
 */

const PAD = /=+$/;

export function bytesToBase64Url(bytes: Uint8Array): string {
  // `btoa` operates on binary strings — assemble one chunk-wise to avoid
  // stack overflows on large inputs.
  let binary = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(PAD, '');
}

export function base64UrlToBytes(input: string): Uint8Array {
  const b64 = input.replace(/-/g, '+').replace(/_/g, '/');
  const pad = b64.length % 4;
  const padded = pad ? b64 + '='.repeat(4 - pad) : b64;
  const binary = atob(padded);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

export function stringToBase64Url(s: string): string {
  return bytesToBase64Url(new TextEncoder().encode(s));
}
