export async function onRequestPost(context) {
  const { request, env } = context;

  // Parse incoming token from the frontend
  let body;
  try {
    body = await request.json();
  } catch {
    return jsonResponse({ success: false, error: "Invalid request body" }, 400);
  }

  const token = body?.token;
  if (!token) {
    return jsonResponse({ success: false, error: "Missing token" }, 400);
  }

  // Get secret key from env variable (set in CF Pages dashboard)
  const secret = env.TURNSTILE_SECRET;
  if (!secret) {
    console.error("TURNSTILE_SECRET env var not set");
    return jsonResponse({ success: false, error: "Server misconfiguration" }, 500);
  }

  // Call Cloudflare's siteverify endpoint
  const verifyRes = await fetch(
    "https://challenges.cloudflare.com/turnstile/v0/siteverify",
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        secret,
        response: token,
        // Optionally bind to client IP for extra security:
        remoteip: request.headers.get("CF-Connecting-IP") ?? undefined,
      }),
    }
  );

  const result = await verifyRes.json();

  if (result.success) {
    return jsonResponse({ success: true });
  } else {
    // result["error-codes"] contains details e.g. "token-already-used"
    return jsonResponse({
      success: false,
      errors: result["error-codes"] ?? ["unknown"],
    }, 403);
  }
}

// Block all non-POST methods
export async function onRequest(context) {
  if (context.request.method === "POST") {
    return onRequestPost(context);
  }
  return jsonResponse({ success: false, error: "Method not allowed" }, 405);
}

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      // Prevent caching of auth responses
      "Cache-Control": "no-store",
    },
  });
}
