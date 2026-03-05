// functions/nonce.js
// Issues a one-time cryptographic nonce for behaviour proof signing.
// Called by the client after mouse movement threshold is reached,
// before Turnstile is revealed. Stored in KV with a 2-minute TTL.

const NONCE_TTL_SECONDS = 120;

export async function onRequestGet(context) {
  const { request, env } = context;

  if (request.headers.get('X-Requested-With') !== 'BetStream-Web') {
    return jsonResponse({ success: false, error: 'Forbidden' }, 403);
  }

  if (!env.NONCE_STORE) {
    console.error('Missing KV binding: NONCE_STORE');
    return jsonResponse({ success: false, error: 'Server misconfiguration' }, 500);
  }

  const raw   = crypto.getRandomValues(new Uint8Array(32));
  const nonce = Array.from(raw).map(b => b.toString(16).padStart(2, '0')).join('');
  const ip    = request.headers.get('CF-Connecting-IP') ?? 'unknown';

  await env.NONCE_STORE.put(
    `nonce:${nonce}`,
    JSON.stringify({ issuedAt: Math.floor(Date.now() / 1000), ip }),
    { expirationTtl: NONCE_TTL_SECONDS }
  );

  return jsonResponse({ nonce });
}

export async function onRequest(context) {
  if (context.request.method === 'GET') return onRequestGet(context);
  return jsonResponse({ success: false, error: 'Method not allowed' }, 405);
}

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
    },
  });
}