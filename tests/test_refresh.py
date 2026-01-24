from fastapi.testclient import TestClient

from tests.conftest import login_user, register_user


def test_refresh_rotates_jti(client: TestClient) -> None:
    register_user(
        client,
        username="alice",
        password="Password123",
        full_name="Alice Example",
        email="alice@example.com",
    )

    token1 = login_user(client, username="alice", password="Password123")

    refresh1 = client.post("/api/auth/refresh", json={"refresh_token": token1["refresh_token"]})
    assert refresh1.status_code == 200, refresh1.text
    token2 = refresh1.json()

    refresh_again_old = client.post("/api/auth/refresh", json={"refresh_token": token1["refresh_token"]})
    assert refresh_again_old.status_code == 401

    refresh_new = client.post("/api/auth/refresh", json={"refresh_token": token2["refresh_token"]})
    assert refresh_new.status_code == 200
