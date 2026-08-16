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
export const dynamic = "force-dynamic";

export async function GET() {
  const backendUrl = process.env.BACKEND_INTERNAL_URL;
  const stealthToken = process.env.STEALTH_TOKEN;

  if (!backendUrl || !stealthToken) {
    return Response.json(
      { error: "BACKEND_INTERNAL_URL / STEALTH_TOKEN not configured on the frontend service" },
      { status: 503 },
    );
  }

  try {
    const res = await fetch(`${backendUrl}/api/metrics/dashboard`, {
      headers: { "X-Stealth-Token": stealthToken },
      cache: "no-store",
    });

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
