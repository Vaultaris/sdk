/**
 * Edge middleware — runs on EVERY request before any route handler.
 *
 * Vaultaris node bindings are not Edge-compatible (they're native), so
 * this middleware only short-circuits requests that obviously can't be
 * authenticated (missing header) and lets the rest fall through to the
 * Route Handlers, where `authorize()` runs against the full client.
 */

import { type NextRequest, NextResponse } from 'next/server';

export function middleware(req: NextRequest) {
  // Skip non-API paths entirely.
  if (!req.nextUrl.pathname.startsWith('/api/')) {
    return NextResponse.next();
  }
  // Health check stays public.
  if (req.nextUrl.pathname === '/api/health') {
    return NextResponse.next();
  }

  const auth = req.headers.get('authorization');
  if (!auth) {
    return NextResponse.json(
      { error: 'Missing Authorization header' },
      { status: 401 },
    );
  }
  return NextResponse.next();
}

export const config = {
  matcher: ['/api/:path*'],
};
