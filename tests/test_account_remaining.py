from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient
import pytest
from sqlalchemy.orm import Session, sessionmaker

from app.api.routes import account
from app.database.models.user import UserDB


@pytest.fixture(autouse=True)
def _disable_account_email_enqueue(monkeypatch: pytest.MonkeyPatch) -> None:
    def _noop_enqueue(*args, **kwargs) -> None:
        return None

    monkeypatch.setattr(account, "_enqueue_email", _noop_enqueue)


def _register(client: TestClient, *, username: str, email: str | None = None) -> None:
    response = client.post(
        "/api/auth/v1/register",
        json={
            "username": username,
            "password": "StrongPass1",
            "email": email if email is not None else f"{username}@example.com",
            "full_name": f"{username.title()} Doe",
        },
    )
    assert response.status_code == 201


def _login_headers(client: TestClient, *, username: str, password: str = "StrongPass1") -> dict[str, str]:
    response = client.post(
        "/api/auth/v1/login",
        data={"username": username, "password": password},
    )
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def test_modify_bio_rejects_too_long(client: TestClient) -> None:
    _register(client, username="alice")
    alice_headers = _login_headers(client, username="alice")

    response = client.patch(
        "/api/account/v1/modify/bio",
        json={"new_bio": "x" * 257},
        headers=alice_headers,
    )

    assert response.status_code == 422
    assert response.json()["detail"] == "settings.account.bio.too_long"


def test_request_data_enforces_cooldown(
    client: TestClient,
    session_factory: sessionmaker[Session],
) -> None:
    _register(client, username="alice")
    alice_headers = _login_headers(client, username="alice")

    first = client.post("/api/account/v1/request/data", headers=alice_headers)
    assert first.status_code == 200
    assert first.json()["message"] == "settings.account.data.sent"

    second = client.post("/api/account/v1/request/data", headers=alice_headers)
    assert second.status_code == 400
    assert second.json()["detail"] == "settings.account.data.too_soon"

    db = session_factory()
    try:
        row = db.query(UserDB).filter(UserDB.username == "alice").one()
        row.data_requested_at = datetime.now(timezone.utc) - timedelta(days=8)
        db.commit()
    finally:
        db.close()

    third = client.post("/api/account/v1/request/data", headers=alice_headers)
    assert third.status_code == 200


def test_delete_account_success_redacts_user(client: TestClient, session_factory: sessionmaker[Session]) -> None:
    _register(client, username="alice", email="alice@example.com")
    alice_headers = _login_headers(client, username="alice")

    response = client.request(
        "DELETE",
        "/api/account/v1/delete",
        json={"password": "StrongPass1"},
        headers=alice_headers,
    )

    assert response.status_code == 200
    assert response.json()["message"] == "settings.account.delete.success"

    db = session_factory()
    try:
        row = db.query(UserDB).filter(UserDB.username == "alice").one()
        assert row.disabled is True
        assert row.full_name == "[redacted]"
        assert row.email == f"[redacted_{row.id}]"
    finally:
        db.close()
