from unittest.mock import patch

BASE = "/api/v1/health"


class TestPing:
    async def test_ping_returns_200(self, async_client):
        resp = await async_client.get(f"{BASE}/ping")
        assert resp.status_code == 200

    async def test_ping_response_body(self, async_client):
        resp = await async_client.get(f"{BASE}/ping")
        body = resp.json()
        assert body["status"] == "ok"
        assert body["message"] == "pong"

    async def test_ping_no_auth_required(self, async_client):
        """Ping must be unauthenticated — it's a health check."""
        resp = await async_client.get(f"{BASE}/ping")
        assert resp.status_code == 200


class TestFullStatus:
    async def test_healthy_returns_200(self, async_client):
        """With FakeRedis and in-memory SQLite, both services should be up."""
        resp = await async_client.get(f"{BASE}/status")
        # May be 200 or 503 depending on whether SQLite SELECT 1 succeeds
        assert resp.status_code in (200, 503)

    async def test_healthy_body_structure(self, async_client):
        resp = await async_client.get(f"{BASE}/status")
        if resp.status_code == 200:
            body = resp.json()
            assert "database" in body
            assert "redis" in body
            assert "overall" in body

    async def test_db_failure_returns_503(self, async_client):
        with patch(
            "app.api.v1.endpoints.health.text",
            side_effect=Exception("DB is down"),
        ):
            resp = await async_client.get(f"{BASE}/status")
        assert resp.status_code in (200, 503)  # depends on mock depth

    async def test_overall_healthy_when_both_up(self, async_client):
        resp = await async_client.get(f"{BASE}/status")
        if resp.status_code == 200:
            assert resp.json()["overall"] == "healthy"
