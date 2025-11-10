import pytest

from empire.server.common.empire import MainMenu
from empire.server.core.db.models import AgentTaskStatus


@pytest.fixture(scope="module")
def agent_communication_service(main: MainMenu):
    return main.agentcommsv2


@pytest.fixture(scope="module")
def agent_task_service(main: MainMenu):
    return main.agenttasksv2


@pytest.fixture(scope="module")
def agent_service(main: MainMenu):
    return main.agentsv2


def test_save_file_non_python(
    agent_task_service,
    agent_communication_service,
    session_local,
    models,
    agent,
    agent_task,
    empire_config,
):
    data = b"This is a test file"
    file_path = r"C:\Users\Public\test.txt"
    with session_local.begin() as db:
        agent_communication_service.save_file(
            db,
            agent,
            file_path,
            data,
            len(data),
            agent_task_service.get_task_for_agent(db, agent, agent_task["id"]),
            "powershell",
        )

    with session_local.begin() as db:
        task = agent_task_service.get_task_for_agent(db, agent, agent_task["id"])
        assert len(task.downloads) == 1
        download = task.downloads[0]
        assert download.filename == "test.txt"
        assert download.size == len(data)
        assert download.get_bytes_file() == data
        assert f"downloads/{agent}/{file_path.replace('\\', '/')}" in download.location


def test_save_file_python(
    agent_task_service,
    agent_communication_service,
    session_local,
    models,
    agent,
    agent_task,
):
    # Python agent compresses the data
    # Also test backslash vs forward slash?
    pass


def test_save_module_file(agent_communication_service, session_local):
    pass


def test__remove_agent(
    agent_service, agent_communication_service, agent, session_local
):
    with session_local.begin() as db:
        assert agent in agent_communication_service.agents
        assert agent_service.get_by_id(db, agent)

        agent_communication_service._remove_agent(db, agent)

        assert agent not in agent_communication_service.agents
        assert not agent_service.get_by_id(db, agent)


def test__get_agent_nonce(main, agent_communication_service, agent, session_local):
    with session_local.begin() as db:
        db_agent = main.agentsv2.get_by_id(db, agent)
        nonce = agent_communication_service._get_agent_nonce(db, agent)

        assert nonce == db_agent.nonce


def test__update_dir_list(agent_communication_service, agent, session_local, models):
    with session_local.begin() as db:
        response = {
            "directory_path": r"C:\Users\Public",
            "directory_name": "Desktop",
            "items": [
                {
                    "name": "test.txt",
                    "path": r"C:\Users\Public\Desktop\test.txt",
                    "is_file": True,
                },
                {
                    "name": "Stuff",
                    "path": r"C:\Users\Public\Desktop\Stuff",
                    "is_file": False,
                },
            ],
        }

        agent_communication_service._update_dir_list(db, agent, response)

        files = (
            db.query(models.AgentFile)
            .filter(models.AgentFile.session_id == agent)
            .all()
        )

        assert len(files) == 3  # noqa: PLR2004

        root = files[0]
        assert root.name == "Desktop"
        assert root.path == r"C:\Users\Public"

        test_txt = files[1]
        assert test_txt.name == "test.txt"
        assert test_txt.path == r"C:\Users\Public\Desktop\test.txt"
        assert test_txt.parent_id == root.id

        stuff = files[2]
        assert stuff.name == "Stuff"
        assert stuff.path == r"C:\Users\Public\Desktop\Stuff"
        assert stuff.parent_id == root.id


def test_update_agent_sysinfo(
    agent_communication_service, session_local, agent, models
):
    listener = "ABC"
    external_ip = "1.2.3.4"
    internal_ip = "4.3.2.1"
    username = "testuser"
    hostname = "testhost"
    os_details = "Windows 10"
    high_integrity = True
    process_name = "test.exe"
    process_id = 1234
    language_version = "3.9.1"
    language = "python"
    architecture = "x64"
    with session_local.begin() as db:
        agent_communication_service.update_agent_sysinfo(
            db,
            agent,
            listener,
            external_ip,
            internal_ip,
            username,
            hostname,
            os_details,
            high_integrity,
            process_name,
            process_id,
            language_version,
            language,
            architecture,
        )

    with session_local.begin() as db:
        agent = db.query(models.Agent).filter(models.Agent.session_id == agent).first()

        # TODO: Should these fields be updated?
        # assert agent.listener == listener
        # assert agent.external_ip == external_ip
        assert agent.internal_ip == internal_ip
        assert agent.username == username
        assert agent.hostname == hostname
        assert agent.os_details == os_details
        assert agent.high_integrity == high_integrity
        assert agent.process_name == process_name
        assert agent.process_id == process_id
        assert agent.language_version == language_version
        assert agent.language == language
        assert agent.architecture == architecture


def test__get_queued_agent_tasks(
    agent_task_service, agent_communication_service, session_local, agent, agent_task
):
    with session_local.begin() as db:
        tasks, _ = agent_task_service.get_tasks(db, agents=[agent])
        assert len(tasks) == 1
        assert all(task.status == AgentTaskStatus.queued for task in tasks)

        queued_tasks = agent_communication_service._get_queued_agent_tasks(db, agent)
        assert len(queued_tasks) == 1
        assert all(task.status == AgentTaskStatus.pulled for task in queued_tasks)


def test__get_queued_agent_temporary_tasks(
    agent_task_service, agent_communication_service, agent
):
    task, _ = agent_task_service.add_temporary_task(agent, "TEST_TASK", "TEST_DATA")

    assert agent_task_service.temporary_tasks[agent][0] == task

    queued_tasks = agent_communication_service._get_queued_agent_temporary_tasks(agent)

    assert queued_tasks[0] == task
    assert agent_task_service.temporary_tasks[agent] == []


def test__handle_agent_staging():
    pass


def test_handle_agent_data():
    pass


def test_handle_agent_request(
    agent_task_service, agent_communication_service, agent, agent_task, monkeypatch
):
    task, _ = agent_task_service.add_temporary_task(
        agent, "TASK_SHELL", "echo 'hello world'"
    )

    packet = agent_communication_service.handle_agent_request(
        agent, "python", "2c103f2c4ed1e59c0b4e2e01821770fa"
    )

    assert packet is not None


def test__handle_agent_response():
    pass


def test__process_agent_packet():
    pass


def _test_autorun_task(
    agent_task_service,
    agent_communication_service,
    agent,
    session_local,
    db,
    listener,
    agent_service,
    main: MainMenu,
):
    mock_autorun_task = [
        {
            "module_id": "powershell_code_execution_invoke_boolang",
            "ignore_language_version_check": False,
            "ignore_admin_check": False,
            "options": {"BooSource": "Hello World"},
            "modified_input": "",
        },
        {
            "module_id": "powershell_code_execution_invoke_ironpython",
            "ignore_language_version_check": False,
            "ignore_admin_check": False,
            "options": {"ipyscript": "Hello World"},
            "modified_input": "",
        },
    ]

    db_listener = main.listenersv2.get_by_name(db, "new-listener-1")
    db_listener.autorun_tasks = mock_autorun_task

    db_agent = agent_service.get_by_name(db, agent)
    db_agent.listener = "new-listener-1"

    agent_communication_service.autorun_tasks(db, agent)

    tasks, total = agent_task_service.get_tasks(db, agents=[agent])

    assert len(tasks) == 2  # noqa: PLR2004
    assert tasks[0].task_name == "TASK_POWERSHELL_CMD_JOB"
    assert tasks[0].module_name == mock_autorun_task[1]["module_id"]
    assert tasks[0].status == "queued"
