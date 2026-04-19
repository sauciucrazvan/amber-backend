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


def _set_verified(session_factory: sessionmaker[Session], username: str) -> None:
    db = session_factory()
    try:
        row = db.query(UserDB).filter(UserDB.username == username).one()
        row.verified = True
        db.commit()
    finally:
        db.close()


def _seed_relationship(
    session_factory: sessionmaker[Session],
    *,
    source_username: str,
    target_username: str,
    relation: str,
) -> None:
    db = session_factory()
    try:
        source = db.query(UserDB).filter(UserDB.username == source_username).one()
        target = db.query(UserDB).filter(UserDB.username == target_username).one()
        db.add(Relationship(user_id=source.id, other_user_id=target.id, relation=relation))
        db.commit()
    finally:
        db.close()


def test_decline_contact_request_success(client: TestClient, session_factory: sessionmaker[Session]) -> None:
    _register(client, username="alice")
    _register(client, username="bob")
    _set_verified(session_factory, "alice")
    _set_verified(session_factory, "bob")

    alice_headers = _login_headers(client, username="alice")
    bob_headers = _login_headers(client, username="bob")

    request_response = client.post(
        "/api/contacts/v1/request",
        json={"username": "bob"},
        headers=alice_headers,
    )
    assert request_response.status_code == 200

    decline_response = client.post(
        "/api/contacts/v1/decline",
        json={"username": "alice"},
        headers=bob_headers,
    )

    assert decline_response.status_code == 200
    assert decline_response.json()["message"] == "contacts.declined"


def test_profile_requires_contact_relation(client: TestClient, session_factory: sessionmaker[Session]) -> None:
    _register(client, username="alice")
    _register(client, username="bob")
    _set_verified(session_factory, "alice")
    _set_verified(session_factory, "bob")

    alice_headers = _login_headers(client, username="alice")

    response = client.get("/api/contacts/v1/profile/bob", headers=alice_headers)

    assert response.status_code == 400
    assert response.json()["detail"] == "contacts.not_added"


def test_profile_blocked_returns_error(client: TestClient, session_factory: sessionmaker[Session]) -> None:
    _register(client, username="alice")
    _register(client, username="bob")
    _set_verified(session_factory, "alice")
    _set_verified(session_factory, "bob")

    _seed_relationship(
        session_factory,
        source_username="alice",
        target_username="bob",
        relation="blocked",
    )

    alice_headers = _login_headers(client, username="alice")

    response = client.get("/api/contacts/v1/profile/bob", headers=alice_headers)

    assert response.status_code == 400
    assert response.json()["detail"] == "contacts.blocked"
