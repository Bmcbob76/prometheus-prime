from starlette import status


def test_get_host_not_found(client, admin_auth_header):
    response = client.get("/api/v2/hosts/9999", headers=admin_auth_header)

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json()["detail"] == "Host not found for id 9999"


def test_get_host(client, host, admin_auth_token, admin_auth_header):
    response = client.get(f"/api/v2/hosts/{host}", headers=admin_auth_header)

    assert response.status_code == status.HTTP_200_OK
    assert response.json()["id"] == host


def test_get_hosts(client, host, admin_auth_header):
    response = client.get("/api/v2/hosts", headers=admin_auth_header)

    assert response.status_code == status.HTTP_200_OK
    assert len(response.json()["records"]) > 0
