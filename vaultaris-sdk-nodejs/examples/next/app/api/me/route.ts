/** `GET /api/me` — any valid token, returns the resolved principal. */

import { authenticate } from '@/lib/vaultaris';

export async function GET(req: Request) {
  const auth = await authenticate(req);
  if (auth instanceof Response) return auth;
  return Response.json({ user: auth });
}
