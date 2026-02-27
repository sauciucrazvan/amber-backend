from fastapi.testclient import TestClient

from tests.conftest import auth_headers, login_user, register_user


def test_modify_fullname(client: TestClient) -> None:
    register_user(
        client,
        username="alice",
        password="Password123",
        full_name="Alice Example",
        email="alice@example.com",
    )

    token = login_user(client, username="alice", password="Password123")

    res = client.patch(
        "/api/account/modify/fullname",
        json={"new_full_name": "Alice Changed"},
        headers=auth_headers(token["access_token"]),
    )
    assert res.status_code == 200, res.text

    me = client.get("/api/account/me", headers=auth_headers(token["access_token"]))
    assert me.status_code == 200
    assert me.json()["full_name"] == "Alice Changed"
