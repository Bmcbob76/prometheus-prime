from starlette import status


def test_get_profile_not_found(client, admin_auth_header):
    response = client.get("/api/v2/malleable-profiles/9999", headers=admin_auth_header)

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json()["detail"] == "Profile not found for id 9999"


def test_get_profile(client, admin_auth_header):
    response = client.get("/api/v2/malleable-profiles/1", headers=admin_auth_header)

    assert response.status_code == status.HTTP_200_OK
    assert response.json()["id"] == 1
    assert len(response.json()["data"]) > 0


def test_get_profiles(client, admin_auth_header):
    response = client.get("/api/v2/malleable-profiles", headers=admin_auth_header)

    assert response.status_code == status.HTTP_200_OK
    assert len(response.json()["records"]) > 0


def test_create_profile(client, admin_auth_header):
    response = client.post(
        "/api/v2/malleable-profiles/",
        headers=admin_auth_header,
        json={"name": "Test Profile", "category": "cat", "data": "x=0;"},
    )

    assert response.status_code == status.HTTP_201_CREATED
    assert response.json()["name"] == "Test Profile"
    assert response.json()["category"] == "cat"
    assert response.json()["data"] == "x=0;"


def test_update_profile_not_found(client, admin_auth_header):
    response = client.put(
        "/api/v2/malleable-profiles/9999",
        headers=admin_auth_header,
        json={"name": "Test Profile", "category": "cat", "data": "x=0;"},
    )

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json()["detail"] == "Profile not found for id 9999"


def test_update_profile(client, admin_auth_header):
    response = client.put(
        "/api/v2/malleable-profiles/1",
        headers=admin_auth_header,
        json={"data": "x=1;"},
    )

    assert response.json()["id"] == 1
    assert response.json()["data"] == "x=1;"


def test_delete_profile(client, admin_auth_header):
    response = client.delete("/api/v2/malleable-profiles/1", headers=admin_auth_header)

    assert response.status_code == status.HTTP_204_NO_CONTENT

    response = client.get("/api/v2/malleable-profiles/1", headers=admin_auth_header)

    assert response.status_code == status.HTTP_404_NOT_FOUND


def test_reset_profiles(client, admin_auth_header):
    response = client.post(
        "/api/v2/malleable-profiles/reset", headers=admin_auth_header
    )
    assert response.status_code == status.HTTP_204_NO_CONTENT

    initial_response = client.get(
        "/api/v2/malleable-profiles", headers=admin_auth_header
    )
    initial_profiles = initial_response.json()["records"]

    response = client.post(
        "/api/v2/malleable-profiles",
        headers=admin_auth_header,
        json={"name": "Test Profile", "category": "cat", "data": "x=0;"},
    )
    assert response.status_code == status.HTTP_201_CREATED

    response = client.post(
        "/api/v2/malleable-profiles/reset", headers=admin_auth_header
    )
    assert response.status_code == status.HTTP_204_NO_CONTENT

    final_response = client.get("/api/v2/malleable-profiles", headers=admin_auth_header)
    final_profiles = final_response.json()["records"]

    assert len(initial_profiles) == len(final_profiles)


def test_reload_profiles(client, admin_auth_header):
    response = client.post(
        "/api/v2/malleable-profiles",
        headers=admin_auth_header,
        json={"name": "Test Profile", "category": "cat", "data": "x=0;"},
    )
    assert response.status_code == status.HTTP_201_CREATED
    new_profile_id = response.json()["id"]

    initial_response = client.get(
        "/api/v2/malleable-profiles", headers=admin_auth_header
    )
    initial_profiles = initial_response.json()["records"]

    response = client.post(
        "/api/v2/malleable-profiles/reload", headers=admin_auth_header
    )
    assert response.status_code == status.HTTP_204_NO_CONTENT

    final_response = client.get("/api/v2/malleable-profiles", headers=admin_auth_header)
    final_profiles = final_response.json()["records"]

    assert len(initial_profiles) == len(final_profiles)
    assert any(profile["id"] == new_profile_id for profile in final_profiles)
