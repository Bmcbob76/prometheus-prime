from starlette import status


def test_agent_logging(client, admin_auth_header, agent, empire_config):
    """
    Test that the agent logs to the agent log file.
    This is super basic and could be expanded later to test responses.
    """
    response = client.post(
        f"/api/v2/agents/{agent}/tasks/shell",
        headers=admin_auth_header,
        json={
            "command": 'echo "Hello World!"',
        },
    )

    assert response.status_code == status.HTTP_201_CREATED

    agent_log_file = empire_config.directories.downloads / agent / "agent.log"
    assert agent_log_file.exists()
    assert f"Tasked {agent} to run TASK_SHELL" in agent_log_file.read_text()
