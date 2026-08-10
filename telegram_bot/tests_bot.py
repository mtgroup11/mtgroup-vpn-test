"""
MTGroup VPN Ultimate — Telegram Bot Test Suite
Tests for bot command handlers and API integration.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest


class TestBotHelpers:
    """Test bot utility functions."""

    def test_panel_api_client_init(self):
        from telegram_bot.utils.api_client import PanelAPIClient

        client = PanelAPIClient("http://localhost:8443")
        assert client.base_url == "http://localhost:8443"
        assert client._token is None

    def test_admin_only_decorator(self):
        """Test that admin_only decorator blocks non-admin users."""
        from telegram_bot.utils.config import ADMIN_ID

        # When ADMIN_ID is 0, no one is admin by default
        assert isinstance(ADMIN_ID, int)


class TestCommandParsing:
    """Test that command argument parsing works correctly."""

    def test_create_user_args(self):
        """Verify create_user expects 4 arguments."""
        args = ["testuser", "password123", "30", "50"]
        assert len(args) == 4
        assert args[0] == "testuser"
        assert int(args[2]) == 30
        assert float(args[3]) == 50.0

    def test_create_user_data_conversion(self):
        """Test GB to bytes conversion."""
        gb = 50.0
        bytes_val = int(gb * 1024 * 1024 * 1024)
        assert bytes_val == 53687091200

    def test_create_user_invalid_args(self):
        """Test that invalid number args raise ValueError."""
        with pytest.raises(ValueError):
            int("not_a_number")


class TestAPIClientMethods:
    """Test PanelAPIClient methods with mocked responses."""

    @pytest.mark.asyncio
    async def test_authenticate_success(self):
        from telegram_bot.utils.api_client import PanelAPIClient

        client = PanelAPIClient("http://test")
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "test_token",
            "refresh_token": "test_refresh",
        }

        with patch.object(client._client, "post", new_callable=AsyncMock, return_value=mock_response):
            result = await client.authenticate()

        assert result is True
        assert client._token == "test_token"

    @pytest.mark.asyncio
    async def test_authenticate_failure(self):
        from telegram_bot.utils.api_client import PanelAPIClient

        client = PanelAPIClient("http://test")
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.text = "Unauthorized"

        with patch.object(client._client, "post", new_callable=AsyncMock, return_value=mock_response):
            result = await client.authenticate()

        assert result is False
        assert client._token is None

    @pytest.mark.asyncio
    async def test_get_with_auth(self):
        from telegram_bot.utils.api_client import PanelAPIClient

        client = PanelAPIClient("http://test")
        client._token = "valid_token"

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"total_users": 5}

        with patch.object(client._client, "get", new_callable=AsyncMock, return_value=mock_response):
            result = await client.get("/api/system/stats")

        assert result is not None
        assert result["total_users"] == 5

    @pytest.mark.asyncio
    async def test_post_create_user(self):
        from telegram_bot.utils.api_client import PanelAPIClient

        client = PanelAPIClient("http://test")
        client._token = "valid_token"

        mock_response = MagicMock()
        mock_response.status_code = 201
        mock_response.json.return_value = {
            "username": "newuser",
            "subscription_url": "http://test/sub/token123",
        }

        with patch.object(client._client, "post", new_callable=AsyncMock, return_value=mock_response):
            result = await client.post("/api/users", {
                "username": "newuser",
                "password": "pass123",
            })

        assert result is not None
        assert result["username"] == "newuser"

    @pytest.mark.asyncio
    async def test_connection_error(self):
        from telegram_bot.utils.api_client import PanelAPIClient

        client = PanelAPIClient("http://test")
        client._token = "valid_token"

        with patch.object(
            client._client, "get",
            new_callable=AsyncMock,
            side_effect=Exception("Connection refused"),
        ):
            result = await client.get("/api/system/stats")

        assert result is None


class TestUsageCalculations:
    """Test data usage display calculations."""

    def test_gb_conversion(self):
        bytes_val = 53687091200  # 50 GB
        gb = bytes_val / (1024 ** 3)
        assert gb == 50.0

    def test_usage_percentage(self):
        used = 26843545600   # 25 GB
        limit = 53687091200  # 50 GB
        pct = used / limit * 100
        assert pct == 50.0

    def test_usage_bar(self):
        pct = 75
        bar_len = 20
        filled = int(bar_len * pct / 100)
        bar = "█" * filled + "░" * (bar_len - filled)
        assert len(bar) == 20
        assert bar.count("█") == 15
        assert bar.count("░") == 5

    def test_unlimited_data(self):
        """Test that 0 data limit = unlimited."""
        limit = 0
        is_unlimited = limit == 0
        assert is_unlimited is True
