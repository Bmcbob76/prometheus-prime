from starlette.status import HTTP_200_OK, HTTP_401_UNAUTHORIZED


def test_authorization_header_authentication(client, admin_auth_token):
    """Test that the standard Authorization header still works"""
    headers = {"Authorization": f"Bearer {admin_auth_token}"}

    resp = client.get("/api/v2/users/", headers=headers)
    assert resp.status_code == HTTP_200_OK


def test_custom_header_authentication(client, admin_auth_token):
    headers = {"X-Empire-Token": f"Bearer {admin_auth_token}"}

    resp = client.get("/api/v2/users/", headers=headers)
    assert resp.status_code == HTTP_200_OK


def test_custom_header_takes_priority(client, admin_auth_token, regular_auth_token):
    # Send both headers - custom header should take priority
    headers = {
        "Authorization": f"Bearer {regular_auth_token}",  # Regular user token
        "X-Empire-Token": f"Bearer {admin_auth_token}",  # Admin token (should be used)
    }

    # Try to access admin endpoint - should succeed because X-Empire-Token has admin token
    resp = client.get("/api/v2/users/", headers=headers)
    assert resp.status_code == HTTP_200_OK


def test_no_authentication_headers(client):
    resp = client.get("/api/v2/users/")
    assert resp.status_code == HTTP_401_UNAUTHORIZED


def test_invalid_token_in_authorization_header(client):
    headers = {"Authorization": "Bearer invalid_token"}

    resp = client.get("/api/v2/users/", headers=headers)
    assert resp.status_code == HTTP_401_UNAUTHORIZED


def test_invalid_token_in_custom_header(client):
    headers = {"X-Empire-Token": "invalid_token"}

    resp = client.get("/api/v2/users/", headers=headers)
    assert resp.status_code == HTTP_401_UNAUTHORIZED
