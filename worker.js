export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // 1️⃣ AUTHENTICATION (your own secret key)
    const clientKey = request.headers.get("X-Auth-Key");
    if (!clientKey || clientKey !== env.AUTH_SECRET) {
      return new Response("Unauthorized", { status: 401 });
    }

    // 2️⃣ FACEBOOK SIGNATURE VALIDATION
    const signature = request.headers.get("X-Hub-Signature-256");
    if (!signature) {
      return new Response("Missing Signature", { status: 403 });
    }

    const bodyText = await request.clone().text();
    const expectedSig =
      "sha256=" +
      await hmacSHA256(bodyText, env.FACEBOOK_APP_SECRET);

    if (signature !== expectedSig) {
      return new Response("Invalid Signature", { status: 403 });
    }

    // 3️⃣ MESSAGE SIZE LIMIT (defense against DoS)
    if (bodyText.length > 50000) {
      return new Response("Payload Too Large", { status: 413 });
    }

    // 4️⃣ DETECT CHANNEL
    let channel = "unknown";

    try {
      const body = JSON.parse(bodyText);

      if (body.object === "page") channel = "messenger";
      if (body.object === "instagram") channel = "instagram";
      // Add more channel checks here

      // 5️⃣ STRIP SENSITIVE FIELDS (optional)
      delete body.entry?.[0]?.changes;
    } catch (err) {
      return new Response("Invalid JSON", { status: 400 });
    }

    // 6️⃣ FORWARD TO N8N
    const n8nUrl = env.N8N_WEBHOOK_URL + `?channel=${channel}`;

    const forward = await fetch(n8nUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Verified": "true", // internal flag
      },
      body: bodyText,
    });

    const result = await forward.text();

    return new Response(result, {
      status: forward.status,
      headers: { "Content-Type": "application/json" },
    });
  },
};

// HMAC function for signature verification
async function hmacSHA256(message, secret) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(message));
  return [...new Uint8Array(sig)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
