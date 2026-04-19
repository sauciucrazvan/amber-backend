from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient
import pytest
from sqlalchemy.orm import Session, sessionmaker

from app.api.routes import auth
from app.database.models.user import UserDB


@pytest.fixture(autouse=True)
def _disable_auth_email_enqueue(monkeypatch: pytest.MonkeyPatch) -> None:
    def _noop_enqueue(*args, **kwargs) -> None:
        return None

    monkeypatch.setattr(auth, "_enqueue_email", _noop_enqueue)


def _register(client: TestClient, *, username: str) -> None:
    response = client.post(
        "/api/auth/v1/register",
        json={
            "username": username,
            "password": "StrongPass1",
            "email": f"{username}@example.com",
            "full_name": f"{username.title()} Doe",
        },
    )
    assert response.status_code == 201


def _login_headers(client: TestClient, *, username: str) -> dict[str, str]:
    response = client.post(
        "/api/auth/v1/login",
        data={"username": username, "password": "StrongPass1"},
    )
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def test_verify_request_success(client: TestClient, session_factory: sessionmaker[Session]) -> None:
    _register(client, username="alice")
    headers = _login_headers(client, username="alice")

    response = client.post("/api/auth/v1/verify/request", headers=headers)

    assert response.status_code == 200
    assert response.json()["message"] == "register.verify.email_sent"

    db = session_factory()
    try:
        row = db.query(UserDB).filter(UserDB.username == "alice").one()
        assert row.verify_code is not None
        assert row.verify_sent_at is not None
    finally:
        db.close()


def test_verify_request_too_soon(client: TestClient, session_factory: sessionmaker[Session]) -> None:
    _register(client, username="alice")
    headers = _login_headers(client, username="alice")

    db = session_factory()
    try:
        row = db.query(UserDB).filter(UserDB.username == "alice").one()
        row.verify_sent_at = datetime.now(timezone.utc)
        row.verify_code = 123456
        db.commit()
    finally:
        db.close()

    response = client.post("/api/auth/v1/verify/request", headers=headers)

    assert response.status_code == 429
    assert response.json()["detail"] == "register.verify.too_soon"


def test_verify_complete_success(client: TestClient, session_factory: sessionmaker[Session]) -> None:
    _register(client, username="alice")
    headers = _login_headers(client, username="alice")

    request_response = client.post("/api/auth/v1/verify/request", headers=headers)
    assert request_response.status_code == 200

    db = session_factory()
    try:
        row = db.query(UserDB).filter(UserDB.username == "alice").one()
        code = str(row.verify_code)
    finally:
        db.close()

    verify_response = client.post("/api/auth/v1/verify", json={"verify_code": code}, headers=headers)

    assert verify_response.status_code == 200
    assert verify_response.json()["message"] == "register.verify.success"

    db = session_factory()
    try:
        row = db.query(UserDB).filter(UserDB.username == "alice").one()
        assert row.verified is True
        assert row.verified_at is not None
    finally:
        db.close()


def test_verify_complete_rejects_expired_code(client: TestClient, session_factory: sessionmaker[Session]) -> None:
    _register(client, username="alice")
    headers = _login_headers(client, username="alice")

    db = session_factory()
    try:
        row = db.query(UserDB).filter(UserDB.username == "alice").one()
        row.verify_code = 654321
        row.verify_sent_at = datetime.now(timezone.utc) - timedelta(minutes=31)
        db.commit()
    finally:
        db.close()

    response = client.post("/api/auth/v1/verify", json={"verify_code": "654321"}, headers=headers)

    assert response.status_code == 400
    assert response.json()["detail"] == "login.recovery.too_late"
