from fastapi.testclient import TestClient

from tests.conftest import auth_headers, login_user, register_user


def test_contacts_request_accept_list_remove(client: TestClient) -> None:
    register_user(
        client,
        username="alice",
        password="Password123",
        full_name="Alice Example",
        email="alice@example.com",
    )
    register_user(
        client,
        username="bob",
        password="Password123",
        full_name="Bob Example",
        email="bob@example.com",
    )

    alice_token = login_user(client, username="alice", password="Password123")
    bob_token = login_user(client, username="bob", password="Password123")

    req = client.post(
        "/api/account/contacts/request",
        json={"username": "bob"},
        headers=auth_headers(alice_token["access_token"]),
    )
    assert req.status_code == 200, req.text

    bob_requests = client.get(
        "/api/account/contacts/requests",
        headers=auth_headers(bob_token["access_token"]),
    )
    assert bob_requests.status_code == 200
    received = bob_requests.json()
    assert any(item["user"]["username"] == "alice" for item in received)

    accept = client.post(
        "/api/account/contacts/accept",
        json={"username": "alice"},
        headers=auth_headers(bob_token["access_token"]),
    )
    assert accept.status_code == 200, accept.text

    alice_contacts = client.get(
        "/api/account/contacts/list",
        headers=auth_headers(alice_token["access_token"]),
    )
    assert alice_contacts.status_code == 200
    assert any(item["user"]["username"] == "bob" for item in alice_contacts.json())

    bob_contacts = client.get(
        "/api/account/contacts/list",
        headers=auth_headers(bob_token["access_token"]),
    )
    assert bob_contacts.status_code == 200
    assert any(item["user"]["username"] == "alice" for item in bob_contacts.json())

    remove = client.post(
        "/api/account/contacts/remove",
        json={"username": "bob"},
        headers=auth_headers(alice_token["access_token"]),
    )
    assert remove.status_code == 200, remove.text

    alice_contacts_after = client.get(
        "/api/account/contacts/list",
        headers=auth_headers(alice_token["access_token"]),
    )
    assert alice_contacts_after.status_code == 200
    assert all(item["user"]["username"] != "bob" for item in alice_contacts_after.json())


def test_contacts_block_unblock(client: TestClient) -> None:
    register_user(
        client,
        username="alice",
        password="Password123",
        full_name="Alice Example",
        email="alice@example.com",
    )
    register_user(
        client,
        username="bob",
        password="Password123",
        full_name="Bob Example",
        email="bob@example.com",
    )

    alice_token = login_user(client, username="alice", password="Password123")

    block = client.post(
        "/api/account/contacts/block",
        json={"username": "bob"},
        headers=auth_headers(alice_token["access_token"]),
    )
    assert block.status_code == 200, block.text

    blocked = client.get(
        "/api/account/contacts/blocked",
        headers=auth_headers(alice_token["access_token"]),
    )
    assert blocked.status_code == 200
    assert any(item["user"]["username"] == "bob" for item in blocked.json())

    unblock = client.post(
        "/api/account/contacts/unblock",
        json={"username": "bob"},
        headers=auth_headers(alice_token["access_token"]),
    )
    assert unblock.status_code == 200, unblock.text

    blocked_after = client.get(
        "/api/account/contacts/blocked",
        headers=auth_headers(alice_token["access_token"]),
    )
    assert blocked_after.status_code == 200
    assert all(item["user"]["username"] != "bob" for item in blocked_after.json())
