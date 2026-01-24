from fastapi.testclient import TestClient


def test_me_requires_auth(client: TestClient) -> None:
    res = client.get("/api/account/me")
    assert res.status_code in (401, 403)


def test_login_wrong_password(client: TestClient) -> None:
    res = client.post(
        "/api/auth/register",
        json={
            "username": "alice",
            "password": "Password123",
            "full_name": "Alice Example",
            "email": "alice@example.com",
        },
    )
    assert res.status_code == 201

    bad = client.post(
        "/api/auth/login",
        data={"username": "alice", "password": "WrongPassword123"},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert bad.status_code == 401
