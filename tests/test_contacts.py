from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

from app.database.models.relationship import Relationship
from app.database.models.user import UserDB


def _register(client: TestClient, *, username: str, full_name: str) -> None:
    response = client.post(
        "/api/auth/v1/register",
        json={
            "username": username,
            "password": "StrongPass1",
            "email": f"{username}@example.com",
            "full_name": full_name,
        },
    )
    assert response.status_code == 201


def _login_headers(client: TestClient, *, username: str) -> dict[str, str]:
    response = client.post(
        "/api/auth/v1/login",
        data={"username": username, "password": "StrongPass1"},
    )
    assert response.status_code == 200
    token = response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def _set_verified(session_factory: sessionmaker[Session], *, username: str, verified: bool = True) -> None:
    db = session_factory()
    try:
        row = db.query(UserDB).filter(UserDB.username == username).one()
        row.verified = verified
        db.commit()
    finally:
        db.close()


def _seed_relationship(
    session_factory: sessionmaker[Session], *, source_username: str, target_username: str, relation: str
) -> None:
    db = session_factory()
    try:
        source = db.query(UserDB).filter(UserDB.username == source_username).one()
        target = db.query(UserDB).filter(UserDB.username == target_username).one()
        db.add(
            Relationship(
                user_id=source.id,
                other_user_id=target.id,
                relation=relation,
            )
        )
        db.commit()
    finally:
        db.close()


def test_request_contact_requires_verified_user(client: TestClient) -> None:
    _register(client, username="alice", full_name="Alice Doe")
    _register(client, username="bob", full_name="Bob Doe")
    alice_headers = _login_headers(client, username="alice")

    response = client.post(
        "/api/contacts/v1/request",
        json={"username": "bob"},
        headers=alice_headers,
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "common.unverified"


def test_request_and_accept_contact_flow(client: TestClient, session_factory: sessionmaker[Session]) -> None:
    _register(client, username="alice", full_name="Alice Doe")
    _register(client, username="bob", full_name="Bob Doe")

    _set_verified(session_factory, username="alice")
    _set_verified(session_factory, username="bob")

    alice_headers = _login_headers(client, username="alice")
    bob_headers = _login_headers(client, username="bob")

    request_response = client.post(
        "/api/contacts/v1/request",
        json={"username": "bob"},
        headers=alice_headers,
    )
    assert request_response.status_code == 200
    assert request_response.json()["message"] == "contacts.requested"

    requests_response = client.get("/api/contacts/v1/requests", headers=bob_headers)
    assert requests_response.status_code == 200
    requested_usernames = [item["user"]["username"] for item in requests_response.json()]
    assert "alice" in requested_usernames

    accept_response = client.post(
        "/api/contacts/v1/accept",
        json={"username": "alice"},
        headers=bob_headers,
    )
    assert accept_response.status_code == 200
    assert accept_response.json()["message"] == "contacts.accepted"

    alice_contacts = client.get("/api/contacts/v1/list", headers=alice_headers)
    bob_contacts = client.get("/api/contacts/v1/list", headers=bob_headers)
    assert alice_contacts.status_code == 200
    assert bob_contacts.status_code == 200

    alice_usernames = [item["user"]["username"] for item in alice_contacts.json()]
    bob_usernames = [item["user"]["username"] for item in bob_contacts.json()]
    assert "bob" in alice_usernames
    assert "alice" in bob_usernames


def test_block_user_removes_contact_from_list(client: TestClient, session_factory: sessionmaker[Session]) -> None:
    _register(client, username="alice", full_name="Alice Doe")
    _register(client, username="bob", full_name="Bob Doe")

    _set_verified(session_factory, username="alice")
    _set_verified(session_factory, username="bob")

    _seed_relationship(
        session_factory,
        source_username="alice",
        target_username="bob",
        relation="contact",
    )

    alice_headers = _login_headers(client, username="alice")

    block_response = client.put(
        "/api/contacts/v1/block",
        json={"username": "bob"},
        headers=alice_headers,
    )
    assert block_response.status_code == 200
    assert block_response.json()["message"] == "contacts.blocked.success"

    contacts_response = client.get("/api/contacts/v1/list", headers=alice_headers)
    assert contacts_response.status_code == 200
    assert contacts_response.json() == []


def test_unblock_user_without_existing_block_returns_error(
    client: TestClient,
    session_factory: sessionmaker[Session],
) -> None:
    _register(client, username="alice", full_name="Alice Doe")
    _register(client, username="bob", full_name="Bob Doe")

    _set_verified(session_factory, username="alice")
    _set_verified(session_factory, username="bob")

    alice_headers = _login_headers(client, username="alice")

    blocked_response = client.get("/api/contacts/v1/blocked", headers=alice_headers)
    assert blocked_response.status_code == 200
    assert blocked_response.json() == []

    unblock_response = client.request(
        "DELETE",
        "/api/contacts/v1/unblock",
        json={"username": "bob"},
        headers=alice_headers,
    )
    assert unblock_response.status_code == 400
    assert unblock_response.json()["detail"] == "contacts.not_blocked"


def test_remove_contact_not_found_returns_error(
    client: TestClient,
    session_factory: sessionmaker[Session],
) -> None:
    _register(client, username="alice", full_name="Alice Doe")
    _register(client, username="bob", full_name="Bob Doe")

    _set_verified(session_factory, username="alice")
    _set_verified(session_factory, username="bob")

    alice_headers = _login_headers(client, username="alice")

    response = client.request(
        "DELETE",
        "/api/contacts/v1/remove",
        json={"username": "bob"},
        headers=alice_headers,
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "contacts.not_found"
