"""
MTGroup VPN Ultimate — Stealth responses

The one response every "you shouldn't be here" path returns, so the panel
is indistinguishable from an unconfigured nginx vhost.
"""

from fastapi.responses import HTMLResponse

# Byte-for-byte the body stock nginx serves for a 404. Every request that
# fails the stealth gate (or comes from a banned IP, or names a subscription
# token that doesn't exist) gets exactly this, with `Server: nginx`. A
# FastAPI-style `{"detail": "Not Found"}` JSON body is itself a fingerprint
# that tells a scanner/censor a Python API lives here.
NGINX_404_BODY = (
    "<html>\r\n<head><title>404 Not Found</title></head>\r\n<body>\r\n"
    "<center><h1>404 Not Found</h1></center>\r\n<hr><center>nginx</center>\r\n"
    "</body>\r\n</html>\r\n"
)


def nginx_404() -> HTMLResponse:
    return HTMLResponse(
        content=NGINX_404_BODY,
        status_code=404,
        headers={"Server": "nginx"},
    )
