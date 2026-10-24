// Server-side proxy for the dashboard's real telemetry.
//
// The backend hides behind stealth_middleware (backend/app/main.py): any
// request without the exact X-Stealth-Token header gets a generic 404, by
// design, so scanners/censors can't tell the API exists. The dashboard page
// (src/app/dashboard/page.tsx) is a client component and calls
// fetch('/api/metrics/dashboard') directly from the browser — which never
// sent that header, so every request 404'd and the page silently fell back
// to its Math.random() simulated data, 100% of the time, in any real
// deployment. This route handler runs server-side only, so the token
// (read from a non-NEXT_PUBLIC_ env var — never bundled into client JS)
// can be attached here without ever reaching the browser.
//
// The backend endpoint additionally requires an admin JWT (node names and
// fleet health are operational intel the shared stealth token alone must
// not unlock), so the caller's Authorization header is forwarded as-is.
// Without one the backend's 401 is passed straight through.
export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  const backendUrl = process.env.BACKEND_INTERNAL_URL;
  const stealthToken = process.env.STEALTH_TOKEN;

  if (!backendUrl || !stealthToken) {
    return Response.json(
      { error: "BACKEND_INTERNAL_URL / STEALTH_TOKEN not configured on the frontend service" },
      { status: 503 },
    );
  }

  const authorization = request.headers.get("authorization");

  try {
    const res = await fetch(`${backendUrl}/api/metrics/dashboard`, {
      headers: {
        "X-Stealth-Token": stealthToken,
        ...(authorization ? { Authorization: authorization } : {}),
      },
      cache: "no-store",
    });

    if (res.status === 401 || res.status === 403) {
      return Response.json({ error: "admin login required" }, { status: res.status });
    }
    if (!res.ok) {
      return Response.json({ error: `backend returned ${res.status}` }, { status: 502 });
    }

    const data = await res.json();
    return Response.json(data);
  } catch (err) {
    return Response.json(
      { error: err instanceof Error ? err.message : "backend unreachable" },
      { status: 502 },
    );
  }
}
