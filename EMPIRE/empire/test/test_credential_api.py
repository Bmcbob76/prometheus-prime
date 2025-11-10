import copy

from starlette import status


def base_credential():
    return {
        "credtype": "hash",
        "domain": "the-domain",
        "username": "user",
        "password": "hunter2",
        "host": "host1",
    }


def test_create_credential(client, admin_auth_header):
    response = client.post(
        "/api/v2/credentials/", headers=admin_auth_header, json=base_credential()
    )

    assert response.status_code == status.HTTP_201_CREATED
    assert response.json()["id"] > 0
    assert response.json()["credtype"] == "hash"
    assert response.json()["domain"] == "the-domain"
    assert response.json()["username"] == "user"
    assert response.json()["password"] == "hunter2"
    assert response.json()["host"] == "host1"


def test_create_credential_unique_constraint_failure(client, admin_auth_header):
    response = client.post(
        "/api/v2/credentials/", headers=admin_auth_header, json=base_credential()
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json()["detail"] == "Credential not created. Duplicate detected."


def test_update_credential_not_found(client, admin_auth_header):
    response = client.put(
        "/api/v2/credentials/9999", headers=admin_auth_header, json=base_credential()
    )

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json()["detail"] == "Credential not found for id 9999"


def test_update_credential_unique_constraint_failure(
    client, admin_auth_header, credential
):
    credential_2 = copy.deepcopy(base_credential())
    credential_2["domain"] = "the-domain-2"
    response = client.post(
        "/api/v2/credentials/", headers=admin_auth_header, json=credential_2
    )
    assert response.status_code == status.HTTP_201_CREATED

    response = client.put(
        f"/api/v2/credentials/{credential}",
        headers=admin_auth_header,
        json=base_credential(),
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json()["detail"] == "Credential not updated. Duplicate detected."


def test_update_credential(client, admin_auth_header, credential):
    response = client.get(
        f"/api/v2/credentials/{credential}", headers=admin_auth_header
    )
    updated_credential = response.json()
    updated_credential["domain"] = "new-domain"
    updated_credential["password"] = "password3"
    response = client.put(
        f"/api/v2/credentials/{updated_credential['id']}",
        headers=admin_auth_header,
        json=updated_credential,
    )

    assert response.status_code == status.HTTP_200_OK
    assert response.json()["domain"] == "new-domain"
    assert response.json()["password"] == "password3"


def test_get_credential_not_found(client, admin_auth_header):
    response = client.get("/api/v2/credentials/9999", headers=admin_auth_header)

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json()["detail"] == "Credential not found for id 9999"


def test_get_credential(client, admin_auth_header, credential):
    response = client.get(
        f"/api/v2/credentials/{credential}", headers=admin_auth_header
    )

    assert response.status_code == status.HTTP_200_OK
    assert response.json()["id"] > 0


def test_get_credentials(client, admin_auth_header):
    response = client.get("/api/v2/credentials", headers=admin_auth_header)

    assert response.status_code == status.HTTP_200_OK
    assert len(response.json()["records"]) > 0


def test_get_credentials_search(client, admin_auth_header, credential):
    response = client.get(
        f"/api/v2/credentials/{credential}", headers=admin_auth_header
    )
    password = response.json()["password"]
    response = client.get(
        f"/api/v2/credentials?search={password[:3]}", headers=admin_auth_header
    )

    assert response.status_code == status.HTTP_200_OK
    assert len(response.json()["records"]) == 1
    assert response.json()["records"][0]["password"] == password

    response = client.get(
        "/api/v2/credentials?search=qwerty", headers=admin_auth_header
    )

    assert response.status_code == status.HTTP_200_OK
    assert len(response.json()["records"]) == 0


def test_delete_credential(client, admin_auth_header, credential):
    response = client.delete(
        f"/api/v2/credentials/{credential}", headers=admin_auth_header
    )

    assert response.status_code == status.HTTP_204_NO_CONTENT

    response = client.get(
        f"/api/v2/credentials/{credential}", headers=admin_auth_header
    )

    assert response.status_code == status.HTTP_404_NOT_FOUND
