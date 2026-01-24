from __future__ import annotations

from collections.abc import Generator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool


@pytest.fixture(scope="session")
def _project_root() -> Path:
    return Path(__file__).resolve().parents[1]


@pytest.fixture(scope="session", autouse=True)
def _ensure_import_path(_project_root: Path) -> None:
    import sys

    if str(_project_root) not in sys.path:
        sys.path.insert(0, str(_project_root))


@pytest.fixture()
def engine() -> Generator:
    from app.database.session import base
    import app.database.models

    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    base.metadata.create_all(bind=engine)
    try:
        yield engine
    finally:
        base.metadata.drop_all(bind=engine)


@pytest.fixture()
def db_session(engine) -> Generator[Session, None, None]:
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture(autouse=True)
def _mock_resend(monkeypatch: pytest.MonkeyPatch) -> None:
    import resend

    if not hasattr(resend, "Emails"):
        return

    if not hasattr(resend.Emails, "send"):
        return

    monkeypatch.setattr(resend.Emails, "send", lambda *args, **kwargs: None)


@pytest.fixture()
def app(engine):
    from app.main import create_app
    from app.database.session import get_db

    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    def _get_test_db() -> Generator[Session, None, None]:
        db = SessionLocal()
        try:
            yield db
        finally:
            db.close()

    application = create_app(init_db=False, enable_rate_limiting=False)

    application.dependency_overrides[get_db] = _get_test_db

    return application


@pytest.fixture()
def client(app) -> Generator[TestClient, None, None]:
    with TestClient(app) as c:
        yield c


def register_user(
    client: TestClient,
    *,
    username: str,
    password: str,
    full_name: str,
    email: str | None = None,
) -> dict:
    payload: dict = {
        "username": username,
        "password": password,
        "full_name": full_name,
    }
    if email is not None:
        payload["email"] = email

    res = client.post("/api/auth/register", json=payload)
    assert res.status_code == 201, res.text
    return res.json()


def login_user(client: TestClient, *, username: str, password: str) -> dict:
    res = client.post(
        "/api/auth/login",
        data={"username": username, "password": password},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert res.status_code == 200, res.text
    return res.json()


def auth_headers(access_token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {access_token}"}
