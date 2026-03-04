// functions/stream.js
// SSE endpoint — validates HMAC stream token, pushes live mock odds

const TOKEN_TTL_SECONDS = 300;

// Mock match data — seed state
const MATCHES = [
  { id: 1, league: 'Premier League', home_team: 'Arsenal',   away_team: 'Chelsea',    score: '1 - 0', minute: 34, home: 2.10, draw: 3.40, away: 3.80 },
  { id: 2, league: 'Premier League', home_team: 'Liverpool', away_team: 'Man City',   score: '0 - 0', minute: 67, home: 2.50, draw: 3.10, away: 2.90 },
  { id: 3, league: 'La Liga',        home_team: 'Barcelona', away_team: 'Real Madrid', score: '2 - 1', minute: 55, home: 1.90, draw: 3.60, away: 4.20 },
  { id: 4, league: 'La Liga',        home_team: 'Atletico',  away_team: 'Sevilla',    score: '0 - 1', minute: 78, home: 1.70, draw: 3.80, away: 5.00 },
  { id: 5, league: 'Bundesliga',     home_team: 'Bayern',    away_team: 'Dortmund',   score: '1 - 1', minute: 42, home: 1.60, draw: 4.00, away: 5.50 },
  { id: 6, league: 'Serie A',        home_team: 'Juventus',  away_team: 'Inter',      score: '0 - 0', minute: 23, home: 2.30, draw: 3.20, away: 3.10 },
];

export async function onRequest(context) {
  const { request, env } = context;

  if (request.method !== 'GET') {
    return new Response('Method not allowed', { status: 405 });
  }

  // ── Extract and validate stream token ─────────────────────────────
  const url = new URL(request.url);
  const rawToken = url.searchParams.get('token');

  if (!rawToken) {
    return new Response('Missing token', { status: 401 });
  }

  if (!env.STREAM_HMAC_SECRET) {
    return new Response('Server misconfiguration', { status: 500 });
  }

  const ip = request.headers.get('CF-Connecting-IP') ?? 'unknown';
  const validation = await validateToken(rawToken, env.STREAM_HMAC_SECRET, ip);

  if (!validation.valid) {
    return new Response(validation.reason, { status: 403 });
  }

  // ── Open SSE stream ────────────────────────────────────────────────
  const { readable, writable } = new TransformStream();
  const writer = writable.getWriter();
  const enc = new TextEncoder();

  const send = (event, data) => {
    writer.write(enc.encode(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`));
  };

  // Start streaming in background
  streamOdds(writer, enc, send, validation.expiry).catch(() => {});

  return new Response(readable, {
    headers: {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache, no-store',
      'X-Accel-Buffering': 'no',
      'X-Content-Type-Options': 'nosniff',
    },
  });
}

async function streamOdds(writer, enc, send, tokenExpiry) {
  // Clone match state for this session (mutations don't affect other sessions)
  const matches = MATCHES.map(m => ({ ...m }));

  // Confirm connection
  send('connected', { message: 'Stream open' });

  let tick = 0;

  while (true) {
    // Check if token has expired server-side
    const now = Math.floor(Date.now() / 1000);
    if (now >= tokenExpiry) {
      send('expired', { message: 'Token expired. Re-verify to continue.' });
      break;
    }

    // Update mock odds — small random fluctuations
    matches.forEach(match => {
      match.home = jitter(match.home, 0.05, 1.05, 15.0);
      match.draw = jitter(match.draw, 0.04, 2.00, 12.0);
      match.away = jitter(match.away, 0.06, 1.05, 20.0);

      // Advance match minute every ~10 ticks
      if (tick % 10 === 0 && match.minute < 90) {
        match.minute = Math.min(90, match.minute + 1);
      }
    });

    send('odds', { matches });

    tick++;
    await sleep(1500); // push update every 1.5 seconds
  }

  try { writer.close(); } catch {}
}

// ── Token validation ───────────────────────────────────────────────
async function validateToken(rawToken, secret, requestIp) {
  let decoded;
  try {
    decoded = atob(rawToken);
  } catch {
    return { valid: false, reason: 'Malformed token' };
  }

  // Format: "ip:expiry:signature"
  const lastColon = decoded.lastIndexOf(':');
  const secondLastColon = decoded.lastIndexOf(':', lastColon - 1);

  if (lastColon === -1 || secondLastColon === -1) {
    return { valid: false, reason: 'Invalid token format' };
  }

  const signature = decoded.slice(lastColon + 1);
  const payload = decoded.slice(0, lastColon);
  const [tokenIp, expiryStr] = [
    decoded.slice(0, secondLastColon),
    decoded.slice(secondLastColon + 1, lastColon),
  ];

  // Check expiry
  const expiry = parseInt(expiryStr);
  if (isNaN(expiry)) return { valid: false, reason: 'Invalid token expiry' };

  const now = Math.floor(Date.now() / 1000);
  if (now >= expiry) return { valid: false, reason: 'Token expired' };

  // Check IP binding
  if (tokenIp !== requestIp) {
    return { valid: false, reason: 'IP mismatch' };
  }

  // Verify HMAC signature
  const expectedSig = await hmacSign(secret, payload);
  if (!timingSafeEqual(signature, expectedSig)) {
    return { valid: false, reason: 'Invalid token signature' };
  }

  return { valid: true, expiry };
}

// ── Helpers ────────────────────────────────────────────────────────
function jitter(value, maxDelta, min, max) {
  const delta = (Math.random() - 0.5) * 2 * maxDelta;
  return Math.max(min, Math.min(max, Math.round((value + delta) * 100) / 100));
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

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

// Timing-safe string comparison to prevent timing attacks
function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}