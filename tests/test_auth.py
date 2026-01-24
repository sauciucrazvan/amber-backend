from fastapi.testclient import TestClient

from tests.conftest import auth_headers, login_user, register_user


def test_register_and_login(client: TestClient) -> None:
    register_user(
        client,
        username="alice",
        password="Password123",
        full_name="Alice Example",
        email="alice@example.com",
    )

    token = login_user(client, username="alice", password="Password123")
    assert token["token_type"] == "bearer"
    assert token["access_token"]
    assert token["refresh_token"]

    me = client.get("/api/account/me", headers=auth_headers(token["access_token"]))
    assert me.status_code == 200
    body = me.json()
    assert body["username"] == "alice"
    assert body["full_name"] == "Alice Example"
