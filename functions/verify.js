// functions/verify.js
// Validates Turnstile token, returns a signed HMAC stream token
// AND a per-session AES-GCM key derived from HMAC(STREAM_HMAC_SECRET, token)
// The session key is transmitted once over TLS and held only in JS memory —
// it is never stored in the DOM, cookies, or localStorage.

const TOKEN_TTL_SECONDS = 300; // 5 minutes

export async function onRequestPost(context) {
  const { request, env } = context;

  // ── Custom header check (raises bar for direct API probing) ────────
  if (request.headers.get('X-Requested-With') !== 'BetStream-Web') {
    return jsonResponse({ success: false, error: 'Forbidden' }, 403);
  }

  // ── Parse body ─────────────────────────────────────────────────────
  let body;
  try {
    body = await request.json();
  } catch {
    return jsonResponse({ success: false, error: 'Invalid request body' }, 400);
  }

  const token = body?.token;
  if (!token) {
    return jsonResponse({ success: false, error: 'Missing token' }, 400);
  }

  // ── Check secrets are configured ──────────────────────────────────
  if (!env.TURNSTILE_SECRET || !env.STREAM_HMAC_SECRET) {
    console.error('Missing env vars: TURNSTILE_SECRET or STREAM_HMAC_SECRET');
    return jsonResponse({ success: false, error: 'Server misconfiguration' }, 500);
  }

  const ip = request.headers.get('CF-Connecting-IP') ?? 'unknown';

  // ── Validate Turnstile token ───────────────────────────────────────
  const verifyRes = await fetch(
    'https://challenges.cloudflare.com/turnstile/v0/siteverify',
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        secret: env.TURNSTILE_SECRET,
        response: token,
        remoteip: ip,
      }),
    }
  );

  const result = await verifyRes.json();

  if (!result.success) {
    return jsonResponse({
      success: false,
      errors: result['error-codes'] ?? ['unknown'],
    }, 403);
  }

  // ── Hostname check ─────────────────────────────────────────────────
  if (result.hostname !== 'nurielwainstein.com') {
    return jsonResponse({ success: false, error: 'Token hostname mismatch' }, 403);
  }

  // ── Issue signed stream token ──────────────────────────────────────
  const expiry = Math.floor(Date.now() / 1000) + TOKEN_TTL_SECONDS;
  const payload = `${ip}:${expiry}`;
  const signature = await hmacSign(env.STREAM_HMAC_SECRET, payload);
  const streamToken = btoa(`${payload}:${signature}`);

  // ── Derive per-session AES-GCM key ────────────────────────────────
  // Key = HMAC-SHA256(STREAM_HMAC_SECRET, "session-key:" + streamToken)
  // Server can re-derive this at stream time from the validated token —
  // no key storage needed. The client receives it once over TLS.
  const sessionKey = await hmacSign(
    env.STREAM_HMAC_SECRET,
    'session-key:' + streamToken
  );

  return jsonResponse({ success: true, streamToken, sessionKey });
}

export async function onRequest(context) {
  if (context.request.method === 'POST') return onRequestPost(context);
  return jsonResponse({ success: false, error: 'Method not allowed' }, 405);
}

// ── HMAC helpers ───────────────────────────────────────────────────
async function hmacSign(secret, message) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw', enc.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(message));
  return Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');
}

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
    },
  });
}