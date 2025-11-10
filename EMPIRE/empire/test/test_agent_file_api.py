import pytest
from starlette import status


@pytest.fixture
def files(session_local, models, agent):
    with session_local.begin() as db:
        root_file = models.AgentFile(
            session_id=agent, name="/", path="/", is_file=False, parent_id=None
        )

        db.add(root_file)
        db.flush()

        file_1 = models.AgentFile(
            session_id=agent,
            name="C:\\",
            path="/C:\\",
            is_file=False,
            parent_id=root_file.id,
        )
        file_2 = models.AgentFile(
            session_id=agent,
            name="D:\\",
            path="/D:\\",
            is_file=False,
            parent_id=root_file.id,
        )

        db.add(file_1)
        db.add(file_2)
        db.flush()

        file_3 = models.AgentFile(
            session_id=agent,
            name="photo.png",
            path="/C:\\photo.png",
            is_file=True,
            parent_id=file_1.id,
        )
        file_4 = models.AgentFile(
            session_id=agent,
            name="Documents",
            path="/C:\\Documents",
            is_file=False,
            parent_id=file_1.id,
        )

        db.add(file_3)
        db.add(file_4)
        db.flush()

        file_ids = [root_file.id, file_1.id, file_2.id, file_3.id, file_4.id]

    yield file_ids

    with session_local.begin() as db:
        db.query(models.AgentFile).delete()


def test_get_root_agent_not_found(client, admin_auth_header):
    response = client.get("/api/v2/agents/abc/files/root", headers=admin_auth_header)
    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json()["detail"] == "Agent not found for id abc"


def test_get_root_not_found(client, admin_auth_header, agent):
    response = client.get(
        f"/api/v2/agents/{agent}/files/root",
        headers=admin_auth_header,
    )
    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert (
        response.json()["detail"]
        == f'File not found for agent {agent} and file path "/"'
    )


def test_get_root(client, admin_auth_header, agent, files):
    expected_children = 2
    response = client.get(
        f"/api/v2/agents/{agent}/files/root", headers=admin_auth_header
    )
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["name"] == "/"
    assert response.json()["path"] == "/"
    assert response.json()["is_file"] is False
    assert response.json()["parent_id"] is None
    assert len(response.json()["children"]) == expected_children


def test_get_file_agent_not_found(client, admin_auth_header):
    response = client.get("/api/v2/agents/abc/files/root", headers=admin_auth_header)
    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json()["detail"] == "Agent not found for id abc"


def test_get_file_not_found(client, admin_auth_header, agent):
    response = client.get(
        f"/api/v2/agents/{agent}/files/9999", headers=admin_auth_header
    )
    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert (
        response.json()["detail"]
        == f"File not found for agent {agent} and file id 9999"
    )


def test_get_file_with_children(client, admin_auth_header, agent, files):
    expected_children = 2
    response = client.get(
        f"/api/v2/agents/{agent}/files/{files[1]}",
        headers=admin_auth_header,
    )
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["name"] == "C:\\"
    assert response.json()["path"] == "/C:\\"
    assert response.json()["is_file"] is False
    assert response.json()["parent_id"] == files[0]
    assert len(response.json()["children"]) == expected_children


def test_get_file_no_children(client, admin_auth_header, agent, files):
    response = client.get(
        f"/api/v2/agents/{agent}/files/{files[3]}",
        headers=admin_auth_header,
    )
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["name"] == "photo.png"
    assert response.json()["path"] == "/C:\\photo.png"
    assert response.json()["is_file"] is True
    assert response.json()["parent_id"] == files[1]
    assert len(response.json()["children"]) == 0
