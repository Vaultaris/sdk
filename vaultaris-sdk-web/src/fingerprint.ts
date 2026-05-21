/**
 * Client-side device fingerprinting for Vaultaris.
 *
 * Collects high-entropy browser signals and produces a deterministic
 * SHA-256 hex digest. The fingerprint is sent to the server via the
 * `X-Device-Fingerprint` header where it is folded into the server-side
 * device hash for stronger device identification.
 *
 * No external dependencies — uses only native Web APIs.
 */

export interface FingerprintComponents {
  screenResolution: string;
  colorDepth: number;
  timezone: string;
  timezoneOffset: number;
  language: string;
  languages: string[];
  platform: string;
  hardwareConcurrency: number;
  maxTouchPoints: number;
  canvasHash: string;
  webglRenderer: string;
  webglVendor: string;
}

/**
 * Collect all available browser signals and return the raw components.
 * Useful for debugging or custom fingerprinting strategies.
 */
export function collectComponents(): FingerprintComponents {
  const screen =
    typeof globalThis.screen !== 'undefined'
      ? `${globalThis.screen.width}x${globalThis.screen.height}`
      : 'unknown';

  const colorDepth =
    typeof globalThis.screen !== 'undefined' ? globalThis.screen.colorDepth : 0;

  const timezone = safeTimezone();
  const timezoneOffset = new Date().getTimezoneOffset();

  const language =
    typeof globalThis.navigator !== 'undefined'
      ? globalThis.navigator.language || 'unknown'
      : 'unknown';

  const languages =
    typeof globalThis.navigator !== 'undefined'
      ? Array.from(globalThis.navigator.languages || [language])
      : [language];

  const platform =
    typeof globalThis.navigator !== 'undefined'
      ? (globalThis.navigator as Navigator & { userAgentData?: { platform?: string } })
          .userAgentData?.platform ||
        globalThis.navigator.platform ||
        'unknown'
      : 'unknown';

  const hardwareConcurrency =
    typeof globalThis.navigator !== 'undefined'
      ? globalThis.navigator.hardwareConcurrency || 0
      : 0;

  const maxTouchPoints =
    typeof globalThis.navigator !== 'undefined'
      ? globalThis.navigator.maxTouchPoints || 0
      : 0;

  const canvasHash = computeCanvasHash();
  const { renderer: webglRenderer, vendor: webglVendor } = computeWebglInfo();

  return {
    screenResolution: screen,
    colorDepth,
    timezone,
    timezoneOffset,
    language,
    languages,
    platform,
    hardwareConcurrency,
    maxTouchPoints,
    canvasHash,
    webglRenderer,
    webglVendor,
  };
}

/**
 * Compute a deterministic SHA-256 hex fingerprint from browser signals.
 * The result is stable across calls on the same device/browser.
 */
export async function computeFingerprint(): Promise<string> {
  const components = collectComponents();

  // Deterministic JSON — sorted keys, no whitespace variance
  const keys = Object.keys(components).sort() as (keyof FingerprintComponents)[];
  const parts: string[] = [];
  for (const key of keys) {
    const val = components[key];
    parts.push(`${key}=${Array.isArray(val) ? val.join(',') : String(val)}`);
  }
  const raw = parts.join('|');

  // SHA-256 via SubtleCrypto (available in all modern browsers + workers)
  const data = new TextEncoder().encode(raw);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = new Uint8Array(hashBuffer);
  return Array.from(hashArray)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function safeTimezone(): string {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || 'unknown';
  } catch {
    return 'unknown';
  }
}

/**
 * Render a specific pattern to a hidden canvas and hash the pixel data.
 * Different GPUs / font renderers produce subtly different output, making
 * this a high-entropy signal.
 */
function computeCanvasHash(): string {
  try {
    const canvas = document.createElement('canvas');
    canvas.width = 200;
    canvas.height = 50;
    const ctx = canvas.getContext('2d');
    if (!ctx) return '';

    // Draw text with specific font stack — rendering differences reveal
    // the GPU pipeline and font rasterizer.
    ctx.textBaseline = 'alphabetic';
    ctx.font = '14px Arial, sans-serif';
    ctx.fillStyle = '#f60';
    ctx.fillRect(10, 1, 62, 20);

    ctx.fillStyle = '#069';
    ctx.fillText('Vaultaris fp', 2, 15);

    ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
    ctx.fillText('Vaultaris fp', 4, 17);

    // Arc — GPU anti-aliasing varies across devices
    ctx.beginPath();
    ctx.arc(50, 30, 10, 0, Math.PI * 2);
    ctx.closePath();
    ctx.fill();

    return canvas.toDataURL();
  } catch {
    return '';
  }
}

/**
 * Extract the unmasked WebGL renderer and vendor strings. These identify
 * the GPU model / driver combination and are very stable per-device.
 */
function computeWebglInfo(): { renderer: string; vendor: string } {
  try {
    const canvas = document.createElement('canvas');
    const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
    if (!gl || !(gl instanceof WebGLRenderingContext)) {
      return { renderer: '', vendor: '' };
    }

    const ext = gl.getExtension('WEBGL_debug_renderer_info');
    if (!ext) return { renderer: '', vendor: '' };

    return {
      renderer: gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) || '',
      vendor: gl.getParameter(ext.UNMASKED_VENDOR_WEBGL) || '',
    };
  } catch {
    return { renderer: '', vendor: '' };
  }
}
