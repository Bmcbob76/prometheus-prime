import pytest
from starlette import status


@pytest.fixture
def processes(session_local, host, agent, models):
    with session_local.begin() as db:
        db_agent = (
            db.query(models.Agent).filter(models.Agent.session_id == agent).first()
        )
        db_agent.process_id = 11
        process1 = models.HostProcess(
            host_id=host,
            process_id=db_agent.process_id,
            process_name="explorer.exe",
            architecture="x86",
            user="CX01N",
        )

        process2 = models.HostProcess(
            host_id=host,
            process_id="12",
            process_name="discord.exe",
            architecture="x86",
            user="Admin",
        )
        db.add(process1)
        db.add(process2)

        processes = [process1.process_id, process2.process_id]

    return processes  # noqa RET504


def test_get_process_host_not_found(client, admin_auth_header):
    response = client.get("/api/v2/hosts/9999/processes", headers=admin_auth_header)

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json()["detail"] == "Host not found for id 9999"


def test_get_process_not_found(client, admin_auth_header, host):
    response = client.get(
        f"/api/v2/hosts/{host}/processes/8888", headers=admin_auth_header
    )

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert (
        response.json()["detail"]
        == f"Process not found for host id {host} and process id 8888"
    )


def test_get_process(client, admin_auth_header, host, processes):
    response = client.get(
        f"/api/v2/hosts/{host}/processes/{processes[0]}",
        headers=admin_auth_header,
    )

    assert response.status_code == status.HTTP_200_OK
    assert response.json()["process_id"] == processes[0]


def test_get_processes(client, admin_auth_header, host, processes):
    response = client.get(f"/api/v2/hosts/{host}/processes/", headers=admin_auth_header)

    assert response.status_code == status.HTTP_200_OK
    assert len(response.json()["records"]) > 0


def test_agent_join(client, admin_auth_header, host, agent, processes):
    response = client.get(f"/api/v2/hosts/{host}/processes/", headers=admin_auth_header)

    assert response.status_code == status.HTTP_200_OK
    assert len([x for x in response.json()["records"] if x["agent_id"] == agent]) == 1
