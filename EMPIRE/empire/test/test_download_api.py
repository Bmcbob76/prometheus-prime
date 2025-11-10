import urllib.parse
from pathlib import Path

from starlette import status


def test_get_download_not_found(client, admin_auth_header):
    response = client.get("/api/v2/downloads/9999", headers=admin_auth_header)

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json()["detail"] == "Download not found for id 9999"


def test_create_download(client, admin_auth_header):
    response = client.post(
        "/api/v2/downloads",
        headers=admin_auth_header,
        files={
            "file": (
                "test-upload-2.yaml",
                Path("./empire/test/test-upload-2.yaml").read_bytes(),
            )
        },
    )

    assert response.status_code == status.HTTP_201_CREATED
    assert response.json()["id"] > 0


def test_create_download_appends_number_if_already_exists(client, admin_auth_header):
    response = client.post(
        "/api/v2/downloads",
        headers=admin_auth_header,
        files={
            "file": (
                "test-upload-2.yaml",
                Path("./empire/test/test-upload-2.yaml").read_bytes(),
            )
        },
    )

    assert response.status_code == status.HTTP_201_CREATED
    assert response.json()["id"] > 0

    response = client.post(
        "/api/v2/downloads",
        headers=admin_auth_header,
        files={
            "file": (
                "test-upload-2.yaml",
                Path("./empire/test/test-upload-2.yaml").read_bytes(),
            )
        },
    )

    assert response.status_code == status.HTTP_201_CREATED
    assert response.json()["id"] > 0
    assert response.json()["location"].endswith(").yaml")
    assert response.json()["filename"].endswith(").yaml")


def test_get_download(client, admin_auth_header, download):
    response = client.get(f"/api/v2/downloads/{download}", headers=admin_auth_header)

    assert response.status_code == status.HTTP_200_OK
    assert response.json()["id"] == download
    assert "test-upload-2" in response.json()["filename"]


def test_download_download(client, admin_auth_header, download):
    response = client.get(
        f"/api/v2/downloads/{download}/download", headers=admin_auth_header
    )

    assert response.status_code == status.HTTP_200_OK
    assert response.headers.get("content-disposition").lower().startswith(
        'attachment; filename="test-upload-2'
    ) or response.headers.get("content-disposition").lower().startswith(
        "attachment; filename*=utf-8''test-upload-2"
    )


def test_get_downloads(client, admin_auth_header):
    min_expected_downloads = 2
    response = client.get("/api/v2/downloads", headers=admin_auth_header)

    assert response.status_code == status.HTTP_200_OK
    assert response.json()["total"] > min_expected_downloads


def test_get_downloads_with_query(client, admin_auth_header):
    response = client.get(
        "/api/v2/downloads?query=gobblygook", headers=admin_auth_header
    )

    assert response.status_code == status.HTTP_200_OK
    assert response.json()["total"] == 0
    assert response.json()["records"] == []

    q = urllib.parse.urlencode({"query": "test-upload"})
    response = client.get(f"/api/v2/downloads?{q}", headers=admin_auth_header)

    assert response.status_code == status.HTTP_200_OK
    assert response.json()["total"] > 1
