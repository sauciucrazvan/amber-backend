from datetime import datetime, timedelta, timezone
import io

from fastapi.testclient import TestClient
import pytest
from sqlalchemy.orm import Session, sessionmaker
from PIL import Image

from app.api.routes import account
from app.database.models.user import UserDB


def _register(client: TestClient, *, username: str, full_name: str, email: str | None = None) -> None:
    response = client.post(
        "/api/auth/v1/register",
        json={
            "username": username,
            "password": "StrongPass1",
            "email": email if email is not None else f"{username}@example.com",
            "full_name": full_name,
        },
    )
    assert response.status_code == 201


def _login_headers(client: TestClient, *, username: str, password: str = "StrongPass1") -> dict[str, str]:
    response = client.post(
        "/api/auth/v1/login",
        data={"username": username, "password": password},
    )
    assert response.status_code == 200
    token = response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(autouse=True)
def _disable_email_enqueue(monkeypatch: pytest.MonkeyPatch) -> None:
    def _noop_enqueue(*args, **kwargs) -> None:
        return None

    monkeypatch.setattr(account, "_enqueue_email", _noop_enqueue)


def test_account_me_returns_current_user(client: TestClient) -> None:
    _register(client, username="alice", full_name="Alice Doe")
    alice_headers = _login_headers(client, username="alice")

    response = client.get("/api/account/v1/me", headers=alice_headers)

    assert response.status_code == 200
    body = response.json()
    assert body["username"] == "alice"
    assert body["full_name"] == "Alice Doe"


def test_modify_fullname_success(client: TestClient) -> None:
    _register(client, username="alice", full_name="Alice Doe")
    alice_headers = _login_headers(client, username="alice")

    response = client.patch(
        "/api/account/v1/modify/fullname",
        json={"new_full_name": "Alice Changed"},
        headers=alice_headers,
    )

    assert response.status_code == 200
    assert response.json()["message"] == "settings.account.name.updated"


def test_modify_password_rejects_wrong_current_password(client: TestClient) -> None:
    _register(client, username="alice", full_name="Alice Doe")
    alice_headers = _login_headers(client, username="alice")

    response = client.patch(
        "/api/account/v1/modify/password",
        json={
            "current_password": "WrongPass1",
            "new_password": "NewStrongPass1",
            "new_password_confirmation": "NewStrongPass1",
        },
        headers=alice_headers,
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "login.incorrectCredentials"


def test_modify_password_success_updates_login_password(client: TestClient) -> None:
    _register(client, username="alice", full_name="Alice Doe")
    alice_headers = _login_headers(client, username="alice")

    response = client.patch(
        "/api/account/v1/modify/password",
        json={
            "current_password": "StrongPass1",
            "new_password": "NewStrongPass1",
            "new_password_confirmation": "NewStrongPass1",
        },
        headers=alice_headers,
    )

    assert response.status_code == 200
    assert response.json()["message"] == "settings.account.password.updated"

    old_login = client.post(
        "/api/auth/v1/login",
        data={"username": "alice", "password": "StrongPass1"},
    )
    assert old_login.status_code == 401

    new_login = client.post(
        "/api/auth/v1/login",
        data={"username": "alice", "password": "NewStrongPass1"},
    )
    assert new_login.status_code == 200


def test_email_change_request_confirm_verify_flow(
    client: TestClient,
    session_factory: sessionmaker[Session],
) -> None:
    _register(client, username="alice", full_name="Alice Doe", email="alice@old.com")
    alice_headers = _login_headers(client, username="alice")

    request_response = client.post(
        "/api/account/v1/modify/email/request",
        json={"new_email": "alice@new.com", "password": "StrongPass1"},
        headers=alice_headers,
    )

    assert request_response.status_code == 200
    assert request_response.json()["message"] == "settings.account.email.confirm_sent"

    db = session_factory()
    try:
        row = db.query(UserDB).filter(UserDB.username == "alice").one()
        confirm_code = str(row.email_change_code)
    finally:
        db.close()

    confirm_response = client.post(
        "/api/account/v1/modify/email/confirm",
        json={"code": confirm_code},
        headers=alice_headers,
    )

    assert confirm_response.status_code == 200
    assert confirm_response.json()["message"] == "settings.account.email.verify_sent"

    db = session_factory()
    try:
        row = db.query(UserDB).filter(UserDB.username == "alice").one()
        verify_code = str(row.email_change_code)
    finally:
        db.close()

    verify_response = client.post(
        "/api/account/v1/modify/email/verify",
        json={"code": verify_code},
        headers=alice_headers,
    )

    assert verify_response.status_code == 200
    assert verify_response.json()["message"] == "settings.account.email.updated"

    db = session_factory()
    try:
        row = db.query(UserDB).filter(UserDB.username == "alice").one()
        assert row.email == "alice@new.com"
        assert row.email_change_new_email is None
        assert row.email_change_code is None
    finally:
        db.close()


def test_recovery_request_and_reset_flow(
    client: TestClient,
    session_factory: sessionmaker[Session],
) -> None:
    _register(client, username="alice", full_name="Alice Doe", email="alice@example.com")

    recovery_response = client.post(
        "/api/account/v1/recovery/request",
        json={"username": "alice"},
    )

    assert recovery_response.status_code == 200
    assert recovery_response.json()["message"] == "login.recovery.sent"

    db = session_factory()
    try:
        row = db.query(UserDB).filter(UserDB.username == "alice").one()
        recovery_code = str(row.recovery_code)
    finally:
        db.close()

    reset_response = client.post(
        "/api/account/v1/recovery/reset",
        json={
            "username": "alice",
            "code": recovery_code,
            "new_password": "RecoveredPass1",
            "new_password_confirmation": "RecoveredPass1",
        },
    )

    assert reset_response.status_code == 200
    assert reset_response.json()["message"] == "login.recovery.success"

    login_response = client.post(
        "/api/auth/v1/login",
        data={"username": "alice", "password": "RecoveredPass1"},
    )
    assert login_response.status_code == 200


def test_modify_fullname_rejects_same_name(client: TestClient) -> None:
    _register(client, username="alice", full_name="Alice Doe")
    alice_headers = _login_headers(client, username="alice")

    response = client.patch(
        "/api/account/v1/modify/fullname",
        json={"new_full_name": "Alice Doe"},
        headers=alice_headers,
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "settings.account.name.same"


def test_modify_fullname_respects_7_day_cooldown(
    client: TestClient,
    session_factory: sessionmaker[Session],
) -> None:
    _register(client, username="alice", full_name="Alice Doe")
    alice_headers = _login_headers(client, username="alice")

    db = session_factory()
    try:
        row = db.query(UserDB).filter(UserDB.username == "alice").one()
        row.full_name_changed_at = datetime.now(timezone.utc)
        db.commit()
    finally:
        db.close()

    response = client.patch(
        "/api/account/v1/modify/fullname",
        json={"new_full_name": "Alice Changed"},
        headers=alice_headers,
    )

    assert response.status_code == 429
    detail = response.json()["detail"]
    assert detail["message"] == "settings.account.name.tooSoon"
    assert detail["remaining_days"] >= 1


def test_email_change_request_rejects_wrong_password(client: TestClient) -> None:
    _register(client, username="alice", full_name="Alice Doe", email="alice@old.com")
    alice_headers = _login_headers(client, username="alice")

    response = client.post(
        "/api/account/v1/modify/email/request",
        json={"new_email": "alice@new.com", "password": "WrongPass1"},
        headers=alice_headers,
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "login.incorrectCredentials"


def test_email_verify_requires_confirm_first(
    client: TestClient,
    session_factory: sessionmaker[Session],
) -> None:
    _register(client, username="alice", full_name="Alice Doe", email="alice@old.com")
    alice_headers = _login_headers(client, username="alice")

    request_response = client.post(
        "/api/account/v1/modify/email/request",
        json={"new_email": "alice@new.com", "password": "StrongPass1"},
        headers=alice_headers,
    )
    assert request_response.status_code == 200

    db = session_factory()
    try:
        row = db.query(UserDB).filter(UserDB.username == "alice").one()
        code = str(row.email_change_code)
    finally:
        db.close()

    verify_response = client.post(
        "/api/account/v1/modify/email/verify",
        json={"code": code},
        headers=alice_headers,
    )

    assert verify_response.status_code == 400
    assert verify_response.json()["detail"] == "settings.account.email.not_confirmed"


def test_recovery_reset_rejects_expired_code(
    client: TestClient,
    session_factory: sessionmaker[Session],
) -> None:
    _register(client, username="alice", full_name="Alice Doe", email="alice@example.com")

    request_response = client.post(
        "/api/account/v1/recovery/request",
        json={"username": "alice"},
    )
    assert request_response.status_code == 200

    db = session_factory()
    try:
        row = db.query(UserDB).filter(UserDB.username == "alice").one()
        row.recovery_sent_at = datetime.now(timezone.utc) - timedelta(minutes=31)
        recovery_code = str(row.recovery_code)
        db.commit()
    finally:
        db.close()

    reset_response = client.post(
        "/api/account/v1/recovery/reset",
        json={
            "username": "alice",
            "code": recovery_code,
            "new_password": "RecoveredPass1",
            "new_password_confirmation": "RecoveredPass1",
        },
    )

    assert reset_response.status_code == 400
    assert reset_response.json()["detail"] == "login.recovery.too_late"


def test_upload_avatar_success(
    client: TestClient,
    session_factory: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _register(client, username="alice", full_name="Alice Doe")
    alice_headers = _login_headers(client, username="alice")

    def _fake_store_avatar_image(*, username: str, file_bytes: bytes, content_type: str) -> str:
        assert username == "alice"
        assert file_bytes == b"png-bytes"
        assert content_type == "image/png"
        return "http://localhost:9000/amber-avatars/avatars/alice/avatar.png"

    monkeypatch.setattr(account, "_store_avatar_image", _fake_store_avatar_image)

    response = client.post(
        "/api/account/v1/upload/avatar",
        files={"file": ("avatar.png", b"png-bytes", "image/png")},
        headers=alice_headers,
    )

    assert response.status_code == 200
    assert response.json()["message"] == "settings.account.avatar.updated"
    assert response.json()["avatar_url"] == "http://localhost:9000/amber-avatars/avatars/alice/avatar.png"

    db = session_factory()
    try:
        row = db.query(UserDB).filter(UserDB.username == "alice").one()
        assert row.avatar_url == "http://localhost:9000/amber-avatars/avatars/alice/avatar.png"
    finally:
        db.close()


def test_prepare_avatar_image_resizes_to_square_256() -> None:
    source_image = Image.new("RGB", (640, 320), color=(12, 34, 56))
    buffer = io.BytesIO()
    source_image.save(buffer, format="PNG")

    processed_bytes = account._prepare_avatar_image(
        file_bytes=buffer.getvalue(),
        content_type="image/png",
    )

    with Image.open(io.BytesIO(processed_bytes)) as processed_image:
        assert processed_image.size == (256, 256)


def test_upload_avatar_rejects_invalid_content_type(client: TestClient) -> None:
    _register(client, username="alice", full_name="Alice Doe")
    alice_headers = _login_headers(client, username="alice")

    response = client.post(
        "/api/account/v1/upload/avatar",
        files={"file": ("avatar.txt", b"not-an-image", "text/plain")},
        headers=alice_headers,
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "settings.account.avatar.invalidType"
