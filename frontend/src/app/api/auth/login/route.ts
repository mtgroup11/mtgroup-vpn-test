// Server-side proxy for admin login.
//
// Same reason as api/metrics/dashboard/route.ts: the backend only answers
// requests that carry X-Stealth-Token, and that token must never reach the
// browser. The browser posts credentials here; this handler adds the token,
// forwards to the backend, and returns the backend's JWT response as-is.
export const dynamic = "force-dynamic";

export async function POST(request: Request) {
  const backendUrl = process.env.BACKEND_INTERNAL_URL;
  const stealthToken = process.env.STEALTH_TOKEN;

  if (!backendUrl || !stealthToken) {
    return Response.json(
      { error: "BACKEND_INTERNAL_URL / STEALTH_TOKEN not configured on the frontend service" },
      { status: 503 },
    );
  }

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return Response.json({ error: "invalid JSON" }, { status: 400 });
  }

  try {
    const res = await fetch(`${backendUrl}/api/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Stealth-Token": stealthToken },
      body: JSON.stringify(body),
      cache: "no-store",
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      const detail = typeof data?.detail === "string" ? data.detail : `login failed (${res.status})`;
      return Response.json({ error: detail }, { status: res.status });
    }
    return Response.json(data);
  } catch (err) {
    return Response.json(
      { error: err instanceof Error ? err.message : "backend unreachable" },
      { status: 502 },
    );
  }
}
