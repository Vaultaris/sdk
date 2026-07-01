/**
 * `GET /api/orders` — token + `orders:read`
 * `DELETE /api/orders?id=ORD-001` — token + `orders:delete`
 */

import { authorize } from '@/lib/vaultaris';

export async function GET(req: Request) {
  const auth = await authorize(req, 'orders', 'read');
  if (auth instanceof Response) return auth;

  return Response.json({
    orders: ['ORD-001', 'ORD-002'],
    servedTo: auth.username,
  });
}

export async function DELETE(req: Request) {
  const auth = await authorize(req, 'orders', 'delete');
  if (auth instanceof Response) return auth;

  const url = new URL(req.url);
  const id = url.searchParams.get('id');
  if (!id) {
    return Response.json({ error: 'missing ?id' }, { status: 400 });
  }
  return Response.json({
    deletedId: id,
    deletedBy: auth.username,
    userId: auth.userId,
  });
}
