from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

from app.database.models.relationship import Relationship
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


def _seed_contact(session_factory: sessionmaker[Session], a: str, b: str) -> None:
    db = session_factory()
    try:
        user_a = db.query(UserDB).filter(UserDB.username == a).one()
        user_b = db.query(UserDB).filter(UserDB.username == b).one()
        db.add(Relationship(user_id=user_a.id, other_user_id=user_b.id, relation="contact"))
        db.commit()
    finally:
        db.close()


def test_direct_conversation_and_messages_flow(client: TestClient, session_factory: sessionmaker[Session]) -> None:
    _register(client, username="alice")
    _register(client, username="bob")
    _seed_contact(session_factory, "alice", "bob")

    alice_headers = _login_headers(client, username="alice")
    bob_headers = _login_headers(client, username="bob")
    bob_id = _user_id(session_factory, "bob")

    open_response = client.post(f"/api/chats/v1/direct/{bob_id}", headers=alice_headers)
    assert open_response.status_code == 200
    conversation_id = open_response.json()["id"]

    send_response = client.post(
        f"/api/chats/v1/{conversation_id}/messages",
        json={"text": "hello bob"},
        headers=alice_headers,
    )
    assert send_response.status_code == 200
    assert send_response.json()["content"]["text"] == "hello bob"

    fetch_response = client.get(f"/api/chats/v1/{conversation_id}/messages", headers=bob_headers)
    assert fetch_response.status_code == 200
    assert len(fetch_response.json()) == 1
    assert fetch_response.json()[0]["content"]["text"] == "hello bob"

    cursor_response = client.post(
        f"/api/chats/v1/{conversation_id}/read-cursor",
        json={"upto_seq": 1},
        headers=bob_headers,
    )
    assert cursor_response.status_code == 200
    assert cursor_response.json()["last_seen_seq"] == 1


def test_chat_fetch_for_non_participant_forbidden(client: TestClient, session_factory: sessionmaker[Session]) -> None:
    _register(client, username="alice")
    _register(client, username="bob")
    _register(client, username="charlie")
    _seed_contact(session_factory, "alice", "bob")

    alice_headers = _login_headers(client, username="alice")
    charlie_headers = _login_headers(client, username="charlie")
    bob_id = _user_id(session_factory, "bob")

    open_response = client.post(f"/api/chats/v1/direct/{bob_id}", headers=alice_headers)
    assert open_response.status_code == 200
    conversation_id = open_response.json()["id"]

    response = client.get(f"/api/chats/v1/{conversation_id}/messages", headers=charlie_headers)

    assert response.status_code == 403
    assert response.json()["detail"] == "conversations.error.not_participating"
