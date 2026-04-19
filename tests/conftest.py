import sys
from collections.abc import Generator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from app.database.models.user import UserDB
from app.database.models.relationship import Relationship
from app.database.models.conversations import Conversation
from app.database.models.conversation_participants import ConversationParticipants
from app.database.models.conversation_read_cursors import ConversationReadCursor
from app.database.models.messages import Messages
from app.database.models.calls import Call
from app.database.models.call_audit_log import CallAuditLog
from app.database.models.call_metrics import CallMetrics
from app.database.session import base, get_db
from app.api.rate_limiter import limiter
from app.main import create_app


@compiles(JSONB, "sqlite")
def _compile_jsonb_sqlite(_type, _compiler, **_kwargs):
    return "JSON"


@pytest.fixture()
def session_factory() -> Generator[sessionmaker[Session], None, None]:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    UserDB.__table__.create(bind=engine)
    Relationship.__table__.create(bind=engine)
    Conversation.__table__.create(bind=engine)
    ConversationParticipants.__table__.create(bind=engine)
    ConversationReadCursor.__table__.create(bind=engine)
    Messages.__table__.create(bind=engine)
    Call.__table__.create(bind=engine)
    CallAuditLog.__table__.create(bind=engine)
    CallMetrics.__table__.create(bind=engine)
    testing_session_factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)

    try:
        yield testing_session_factory
    finally:
        CallMetrics.__table__.drop(bind=engine)
        CallAuditLog.__table__.drop(bind=engine)
        Call.__table__.drop(bind=engine)
        Messages.__table__.drop(bind=engine)
        ConversationReadCursor.__table__.drop(bind=engine)
        ConversationParticipants.__table__.drop(bind=engine)
        Conversation.__table__.drop(bind=engine)
        Relationship.__table__.drop(bind=engine)
        UserDB.__table__.drop(bind=engine)
        engine.dispose()


@pytest.fixture()
def client(session_factory: sessionmaker[Session]) -> Generator[TestClient, None, None]:
    def override_get_db() -> Generator[Session, None, None]:
        db = session_factory()
        try:
            yield db
        finally:
            db.close()

    previous_limiter_enabled = limiter.enabled
    limiter.enabled = False

    app = create_app(init_db=False, enable_rate_limiting=False)
    app.dependency_overrides[get_db] = override_get_db

    try:
        with TestClient(app) as test_client:
            yield test_client
    finally:
        app.dependency_overrides.clear()
        limiter.enabled = previous_limiter_enabled


@pytest.fixture()
def rate_limited_client(session_factory: sessionmaker[Session]) -> Generator[TestClient, None, None]:
    def override_get_db() -> Generator[Session, None, None]:
        db = session_factory()
        try:
            yield db
        finally:
            db.close()

    previous_limiter_enabled = limiter.enabled
    limiter.enabled = True

    app = create_app(init_db=False, enable_rate_limiting=True)
    app.dependency_overrides[get_db] = override_get_db

    try:
        with TestClient(app) as test_client:
            yield test_client
    finally:
        app.dependency_overrides.clear()
        limiter.enabled = previous_limiter_enabled
