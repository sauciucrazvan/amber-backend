import pytest
from starlette.websockets import WebSocketDisconnect

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

from app.ws import connection_manager
from app.ws import call_signaling


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


def _access_token(client: TestClient, *, username: str) -> str:
    response = client.post(
        "/api/auth/v1/login",
        data={"username": username, "password": "StrongPass1"},
    )
    assert response.status_code == 200
    return response.json()["access_token"]


@pytest.fixture(autouse=True)
def _override_ws_get_session(
    monkeypatch: pytest.MonkeyPatch,
    session_factory: sessionmaker[Session],
) -> None:
    monkeypatch.setattr(connection_manager, "getSession", session_factory)
    monkeypatch.setattr(call_signaling, "getSession", session_factory)


def test_websocket_rejects_missing_token(client: TestClient) -> None:
    with pytest.raises(WebSocketDisconnect) as exc_info:
        with client.websocket_connect("/ws/ping"):
            pass

    assert exc_info.value.code == 1008


def test_websocket_ping_pong_and_invalid_payload(client: TestClient) -> None:
    _register(client, username="alice")
    token = _access_token(client, username="alice")

    with client.websocket_connect(f"/ws/ping?token={token}") as ws:
        ws.send_text("ping")
        assert ws.receive_text() == "pong"

        ws.send_text("{bad-json")
        error_payload = ws.receive_json()
        assert error_payload["type"] == "error"
        assert error_payload["code"] == "signal.invalid_json"

        ws.send_json({"event": "unknown.event"})
        unsupported_payload = ws.receive_json()
        assert unsupported_payload["type"] == "error"
        assert unsupported_payload["code"] == "signal.unsupported_event"
