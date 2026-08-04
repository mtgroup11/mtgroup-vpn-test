import httpx
from typing import Optional
from .config import logger, API_BASE_URL, ADMIN_USERNAME, ADMIN_PASSWORD

class PanelAPIClient:
    """Async HTTP client for communicating with the MTGroup API."""

    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self._token: Optional[str] = None
        self._client = httpx.AsyncClient(timeout=15.0)

    async def authenticate(self) -> bool:
        """Authenticate with the panel and obtain a JWT token."""
        try:
            response = await self._client.post(
                f"{self.base_url}/api/auth/login",
                json={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD},
            )
            if response.status_code == 200:
                data = response.json()
                self._token = data["access_token"]
                logger.info("Telegram bot authenticated with panel")
                return True
            else:
                logger.error("Authentication failed: %s", response.text)
                return False
        except Exception as e:
            logger.error("Failed to connect to panel API: %s", e)
            return False

    @property
    def headers(self) -> dict:
        return {"Authorization": f"Bearer {self._token}"} if self._token else {}

    async def get(self, path: str) -> Optional[dict]:
        try:
            response = await self._client.get(
                f"{self.base_url}{path}",
                headers=self.headers,
            )
            if response.status_code == 401:
                await self.authenticate()
                response = await self._client.get(
                    f"{self.base_url}{path}",
                    headers=self.headers,
                )
            return response.json() if response.status_code == 200 else None
        except Exception as e:
            logger.error("API GET %s failed: %s", path, e)
            return None

    async def post(self, path: str, data: dict) -> Optional[dict]:
        try:
            response = await self._client.post(
                f"{self.base_url}{path}",
                json=data,
                headers=self.headers,
            )
            if response.status_code == 401:
                await self.authenticate()
                response = await self._client.post(
                    f"{self.base_url}{path}",
                    json=data,
                    headers=self.headers,
                )
            return response.json() if response.status_code in (200, 201) else None
        except Exception as e:
            logger.error("API POST %s failed: %s", path, e)
            return None

    async def patch(self, path: str, data: dict) -> Optional[dict]:
        try:
            response = await self._client.patch(
                f"{self.base_url}{path}",
                json=data,
                headers=self.headers,
            )
            if response.status_code == 401:
                await self.authenticate()
                response = await self._client.patch(
                    f"{self.base_url}{path}",
                    json=data,
                    headers=self.headers,
                )
            return response.json() if response.status_code == 200 else None
        except Exception as e:
            logger.error("API PATCH %s failed: %s", path, e)
            return None

    async def delete(self, path: str) -> Optional[dict]:
        try:
            response = await self._client.delete(
                f"{self.base_url}{path}",
                headers=self.headers,
            )
            if response.status_code == 401:
                await self.authenticate()
                response = await self._client.delete(
                    f"{self.base_url}{path}",
                    headers=self.headers,
                )
            return response.json() if response.status_code == 200 else None
        except Exception as e:
            logger.error("API DELETE %s failed: %s", path, e)
            return None

    async def close(self):
        await self._client.aclose()


# Singleton instance
api = PanelAPIClient(API_BASE_URL)
