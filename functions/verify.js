// functions/verify.js
// Validates Turnstile token + mouse-movement behaviour proof,
// returns signed HMAC stream token + AES session key.
//
// Two endpoints:
//   GET  /nonce  — issues a one-time nonce the client uses to sign its behaviour proof
//   POST /verify — validates proof + Turnstile token, issues stream credentials
//
// Behaviour proof flow:
//   1. Client accumulates mouse movement distance
//   2. Once MIN_MOUSE_DIST px is reached, client fetches GET /nonce
//   3. Turnstile widget is revealed
//   4. On Turnstile success, client builds:
//        payload = "moved:1|dist:NNN|ts:TTTT"
//        proof   = { payload, sig: HMAC(nonce, payload), nonce }
//   5. POST /verify receives { token, behaviourProof }
//   6. Server looks up nonce in KV, verifies HMAC, checks dist threshold
//      and timestamp freshness, then deletes nonce (one-time use)
//
// Requires Cloudflare KV binding: NONCE_STORE

const TOKEN_TTL_SECONDS    = 300;
const NONCE_TTL_SECONDS    = 120;  // nonce expires if unused within 2 minutes
const MIN_MOUSE_DIST_PX    = 80;   // must match client threshold
const PROOF_TS_TOLERANCE_S = 30;   // proof timestamp must be within 30s of server time

export async function onRequest(context) {
  const { request } = context;
  const url = new URL(request.url);

  if (url.pathname.endsWith('/nonce') && request.method === 'GET') {
    return handleNonce(context);
  }
  if (request.method === 'POST') {
    return handleVerify(context);
  }
  return jsonResponse({ success: false, error: 'Method not allowed' }, 405);
}

// ── GET /nonce ─────────────────────────────────────────────────────
// Issues a 32-byte random nonce stored in KV with the requester's IP.
// The client uses it as an HMAC key to sign its behaviour proof.
// One-time use — deleted the moment /verify consumes it.
async function handleNonce(context) {
  const { request, env } = context;

  if (request.headers.get('X-Requested-With') !== 'BetStream-Web') {
    return jsonResponse({ success: false, error: 'Forbidden' }, 403);
  }

  if (!env.NONCE_STORE) {
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

  return jsonResponse({ nonce }, 200);
}

// ── POST /verify ───────────────────────────────────────────────────
async function handleVerify(context) {
  const { request, env } = context;

  if (request.headers.get('X-Requested-With') !== 'BetStream-Web') {
    return jsonResponse({ success: false, error: 'Forbidden' }, 403);
  }

  let body;
  try { body = await request.json(); }
  catch { return jsonResponse({ success: false, error: 'Invalid request body' }, 400); }

  const { token, behaviourProof } = body ?? {};

  if (!token) return jsonResponse({ success: false, error: 'Missing token' }, 400);

  if (!env.TURNSTILE_SECRET || !env.STREAM_HMAC_SECRET || !env.NONCE_STORE) {
    return jsonResponse({ success: false, error: 'Server misconfiguration' }, 500);
  }

  const ip = request.headers.get('CF-Connecting-IP') ?? 'unknown';

  // ── Validate behaviour proof first ────────────────────────────────
  if (!behaviourProof) {
    return jsonResponse({ success: false, error: 'Missing behaviour proof' }, 403);
  }

  const proofResult = await validateBehaviourProof(behaviourProof, ip, env);
  if (!proofResult.valid) {
    return jsonResponse({ success: false, error: proofResult.reason }, 403);
  }

  // ── Validate Turnstile token ───────────────────────────────────────
  const verifyRes = await fetch(
    'https://challenges.cloudflare.com/turnstile/v0/siteverify',
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ secret: env.TURNSTILE_SECRET, response: token, remoteip: ip }),
    }
  );

  const result = await verifyRes.json();

  if (!result.success) {
    return jsonResponse({ success: false, errors: result['error-codes'] ?? ['unknown'] }, 403);
  }

  if (result.hostname !== 'nurielwainstein.com') {
    return jsonResponse({ success: false, error: 'Token hostname mismatch' }, 403);
  }

  // ── Issue stream token + AES session key ───────────────────────────
  const expiry      = Math.floor(Date.now() / 1000) + TOKEN_TTL_SECONDS;
  const payload     = `${ip}:${expiry}`;
  const signature   = await hmacSign(env.STREAM_HMAC_SECRET, payload);
  const streamToken = btoa(`${payload}:${signature}`);
  const sessionKey  = await hmacSign(env.STREAM_HMAC_SECRET, 'session-key:' + streamToken);

  return jsonResponse({ success: true, streamToken, sessionKey });
}

// ── Behaviour proof validation ─────────────────────────────────────
// Expected payload format: "moved:1|dist:NNN|ts:TTTT"
async function validateBehaviourProof(proof, requestIp, env) {
  const { payload, sig, nonce } = proof ?? {};

  if (!payload || !sig || !nonce) {
    return { valid: false, reason: 'Incomplete behaviour proof' };
  }

  // 1. Nonce must exist in KV (not expired, not already used)
  const stored = await env.NONCE_STORE.get(`nonce:${nonce}`, { type: 'json' });
  if (!stored) {
    return { valid: false, reason: 'Invalid or expired nonce' };
  }

  // 2. Delete immediately — one-time use, prevents replay
  await env.NONCE_STORE.delete(`nonce:${nonce}`);

  // 3. IP binding — nonce must be redeemed from the same IP it was issued to
  if (stored.ip !== requestIp) {
    return { valid: false, reason: 'Nonce IP mismatch' };
  }

  // 4. Verify HMAC(nonce, payload) — proves payload wasn't tampered with
  const expectedSig = await hmacSign(nonce, payload);
  if (!timingSafeEqual(sig, expectedSig)) {
    return { valid: false, reason: 'Invalid behaviour proof signature' };
  }

  // 5. Parse payload fields
  const fields = {};
  for (const part of payload.split('|')) {
    const colon = part.indexOf(':');
    if (colon !== -1) fields[part.slice(0, colon)] = part.slice(colon + 1);
  }

  // 6. Mouse movement threshold
  if (fields.moved !== '1') {
    return { valid: false, reason: 'No mouse movement detected' };
  }

  const dist = parseFloat(fields.dist ?? '0');
  if (isNaN(dist) || dist < MIN_MOUSE_DIST_PX) {
    return { valid: false, reason: 'Insufficient mouse movement' };
  }

  // 7. Timestamp freshness — prevents pre-built proof replay
  const proofTs = parseInt(fields.ts ?? '0');
  const now     = Math.floor(Date.now() / 1000);
  if (isNaN(proofTs) || Math.abs(now - proofTs) > PROOF_TS_TOLERANCE_S) {
    return { valid: false, reason: 'Behaviour proof timestamp out of range' };
  }

  return { valid: true };
}

// ── Helpers ────────────────────────────────────────────────────────
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

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
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