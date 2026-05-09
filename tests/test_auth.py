from fastapi.testclient import TestClient


def _register_payload(*, username: str = "newuser") -> dict:
    return {
        "username": username,
        "password": "StrongPass1",
        "email": f"{username}@example.com",
        "full_name": "New User",
    }


def test_register_success(client: TestClient) -> None:
    response = client.post("/api/auth/v1/register", json=_register_payload(username="Mixed.Case"))

    assert response.status_code == 201
    body = response.json()
    assert body["username"] == "mixed.case"
    assert body["email"] == "Mixed.Case@example.com"
    assert body["full_name"] == "New User"
    assert body["disabled"] is False
    assert body["verified"] is False


def test_register_rejects_weak_password(client: TestClient) -> None:
    payload = _register_payload()
    payload["password"] = "weakpass"

    response = client.post("/api/auth/v1/register", json=payload)

    assert response.status_code == 422
    assert response.json()["detail"] == "register.invalidPassword"


def test_login_success_returns_tokens(client: TestClient) -> None:
    client.post("/api/auth/v1/register", json=_register_payload(username="alice"))

    response = client.post(
        "/api/auth/v1/login",
        data={"username": "alice", "password": "StrongPass1"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["token_type"] == "bearer"
    assert isinstance(body["access_token"], str) and body["access_token"]
    assert isinstance(body["refresh_token"], str) and body["refresh_token"]


def test_login_rejects_invalid_credentials(client: TestClient) -> None:
    response = client.post(
        "/api/auth/v1/login",
        data={"username": "missing", "password": "StrongPass1"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "login.incorrectCredentials"


def test_login_locks_after_five_failed_attempts(client: TestClient) -> None:
    client.post(
        "/api/auth/v1/register",
        json={
            "username": "locked",
            "password": "StrongPass1",
            "email": "locked@example.com",
            "full_name": "Locked User",
        },
    )

    for _ in range(4):
        response = client.post(
            "/api/auth/v1/login",
            data={"username": "locked", "password": "WrongPass1"},
        )
        assert response.status_code == 401
        assert response.json()["detail"] == "login.incorrectCredentials"

    response = client.post(
        "/api/auth/v1/login",
        data={"username": "locked", "password": "WrongPass1"},
    )

    assert response.status_code == 429
    assert response.json()["detail"] == "login.locked"


def test_refresh_success_returns_new_refresh_token(client: TestClient) -> None:
    client.post("/api/auth/v1/register", json=_register_payload(username="bob"))
    login_response = client.post(
        "/api/auth/v1/login",
        data={"username": "bob", "password": "StrongPass1"},
    )
    first_refresh_token = login_response.json()["refresh_token"]

    refresh_response = client.post(
        "/api/auth/v1/refresh",
        json={"refresh_token": first_refresh_token},
    )

    assert refresh_response.status_code == 200
    body = refresh_response.json()
    assert body["token_type"] == "bearer"
    assert isinstance(body["access_token"], str) and body["access_token"]
    assert body["refresh_token"] != first_refresh_token


def test_refresh_rejects_access_token(client: TestClient) -> None:
    client.post("/api/auth/v1/register", json=_register_payload(username="charlie"))
    login_response = client.post(
        "/api/auth/v1/login",
        data={"username": "charlie", "password": "StrongPass1"},
    )
    access_token = login_response.json()["access_token"]

    response = client.post("/api/auth/v1/refresh", json={"refresh_token": access_token})

    assert response.status_code == 401
    assert response.json()["detail"] == "Could not validate credentials"
