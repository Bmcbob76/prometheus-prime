import re

import pytest

from empire.server.common.empire import MainMenu


@pytest.fixture(scope="module")
def agent_service(main: MainMenu):
    return main.agentsv2


def test_save_agent_log(agent_service, agent, empire_config):
    agent_service.save_agent_log(agent, "test log 1 string")

    agent_service.save_agent_log(agent, b"test log 2 bytes")

    path = empire_config.directories.downloads / agent / "agent.log"

    text = path.read_text().split("\n")
    text = text[text.index("test log 1 string") - 1 :]

    assert re.match(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} : $", text[0])
    assert text[1] == "test log 1 string"

    assert re.match(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} : $", text[3])
    assert text[4] == "test log 2 bytes"
