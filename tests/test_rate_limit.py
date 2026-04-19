from fastapi.testclient import TestClient


def test_write_rate_limit_triggers_429(rate_limited_client: TestClient) -> None:
    seen_429 = False

    for index in range(35):
        response = rate_limited_client.post(
            "/api/auth/v1/register",
            json={
                "username": f"rluser{index}",
                "password": "StrongPass1",
                "email": f"rluser{index}@example.com",
                "full_name": "Rate Limit User",
            },
        )
        if response.status_code == 429:
            seen_429 = True
            break

    assert seen_429 is True
