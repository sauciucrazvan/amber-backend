from datetime import datetime, timezone

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

from app.database.models.calls import Call
from app.database.models.call_audit_log import CallAuditLog
from app.database.models.call_metrics import CallMetrics
from app.database.models.user import UserDB


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


def _user_id(session_factory: sessionmaker[Session], username: str) -> int:
    db = session_factory()
    try:
        return db.query(UserDB).filter(UserDB.username == username).one().id
    finally:
        db.close()


def _seed_call(
    session_factory: sessionmaker[Session],
    *,
    caller_id: int,
    callee_id: int,
    status: str,
) -> str:
    db = session_factory()
    try:
        call = Call(
            caller_user_id=caller_id,
            callee_user_id=callee_id,
            status=status,
            call_mode="video",
            started_at=datetime.now(timezone.utc) if status == "accepted" else None,
        )
        db.add(call)
        db.commit()
        db.refresh(call)
        return call.id
    finally:
        db.close()


def test_calls_history_and_detail(client: TestClient, session_factory: sessionmaker[Session]) -> None:
    _register(client, username="alice")
    _register(client, username="bob")

    alice_headers = _login_headers(client, username="alice")
    alice_id = _user_id(session_factory, "alice")
    bob_id = _user_id(session_factory, "bob")
    call_id = _seed_call(session_factory, caller_id=alice_id, callee_id=bob_id, status="accepted")

    history = client.get("/api/calls/v1/history", headers=alice_headers)
    assert history.status_code == 200
    assert history.json()["total"] >= 1

    detail = client.get(f"/api/calls/v1/{call_id}", headers=alice_headers)
    assert detail.status_code == 200
    assert detail.json()["call_id"] == call_id


def test_end_call_changes_status(client: TestClient, session_factory: sessionmaker[Session]) -> None:
    _register(client, username="alice")
    _register(client, username="bob")

    alice_headers = _login_headers(client, username="alice")
    alice_id = _user_id(session_factory, "alice")
    bob_id = _user_id(session_factory, "bob")
    call_id = _seed_call(session_factory, caller_id=alice_id, callee_id=bob_id, status="accepted")

    response = client.post(
        f"/api/calls/v1/{call_id}/end",
        json={"reason": "ended"},
        headers=alice_headers,
    )

    assert response.status_code == 200
    assert response.json()["status"] == "ended"


def test_call_audit_logs_and_metrics_endpoints(client: TestClient, session_factory: sessionmaker[Session]) -> None:
    _register(client, username="alice")
    _register(client, username="bob")

    alice_headers = _login_headers(client, username="alice")
    alice_id = _user_id(session_factory, "alice")
    bob_id = _user_id(session_factory, "bob")
    call_id = _seed_call(session_factory, caller_id=alice_id, callee_id=bob_id, status="accepted")

    db = session_factory()
    try:
        db.add(CallAuditLog(call_id=call_id, user_id=alice_id, event="test_event", details="ok"))
        db.add(CallMetrics(call_id=call_id, invites_sent=1, accepts_received=1))
        db.commit()
    finally:
        db.close()

    logs = client.get(f"/api/calls/v1/{call_id}/audit-logs", headers=alice_headers)
    assert logs.status_code == 200
    assert logs.json()["audit_logs"][0]["event"] == "test_event"

    metrics = client.get(f"/api/calls/v1/{call_id}/metrics", headers=alice_headers)
    assert metrics.status_code == 200
    assert metrics.json()["invites_sent"] == 1
    assert metrics.json()["accepts_received"] == 1
