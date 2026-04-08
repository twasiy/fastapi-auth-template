from uuid import uuid4

from app.core.security import create_access_token, verify_access_token


class TestBearerAuth:
    async def test_valid_token_grants_access(
        self, async_client, active_verified_user, auth_headers
    ):
        resp = await async_client.get("/api/v1/users/me", headers=auth_headers)
        assert resp.status_code == 200

    async def test_missing_token_returns_403(self, async_client):
        resp = await async_client.get("/api/v1/users/me")
        assert resp.status_code == 403

    async def test_malformed_bearer_returns_400(self, async_client):
        resp = await async_client.get(
            "/api/v1/users/me", headers={"Authorization": "Bearer notavalidjwt"}
        )
        assert resp.status_code == 400

    async def test_wrong_scheme_returns_403(self, async_client, active_verified_user):
        token = create_access_token(active_verified_user.id)
        resp = await async_client.get(
            "/api/v1/users/me", headers={"Authorization": f"Basic {token}"}
        )
        assert resp.status_code == 403

    async def test_blacklisted_token_returns_401(
        self, async_client, active_verified_user, redis_service
    ):
        token = create_access_token(active_verified_user.id)
        payload = verify_access_token(token)
        await redis_service.blacklist_token(payload["jti"], expiry_seconds=3600)

        resp = await async_client.get(
            "/api/v1/users/me", headers={"Authorization": f"Bearer {token}"}
        )
        assert resp.status_code == 401
        assert "revoked" in resp.json()["detail"].lower()

    async def test_token_for_nonexistent_user_returns_404(self, async_client):
        token = create_access_token(uuid4())  # random UUID — no user in DB
        resp = await async_client.get(
            "/api/v1/users/me", headers={"Authorization": f"Bearer {token}"}
        )
        assert resp.status_code == 404

    async def test_inactive_user_returns_403(self, async_client, inactive_user):
        token = create_access_token(inactive_user.id)
        resp = await async_client.get(
            "/api/v1/users/me", headers={"Authorization": f"Bearer {token}"}
        )
        assert resp.status_code == 403
        assert "disabled" in resp.json()["detail"].lower()
