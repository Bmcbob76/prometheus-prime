import pytest


def pytest_addoption(parser):
    parser.addoption(
        "--runslow", action="store_true", default=False, help="run slow tests"
    )
    parser.addoption(
        "--nodocker",
        action="store_true",
        default=False,
        help="skip tests that fail in docker",
    )


def pytest_configure(config):
    config.addinivalue_line("markers", "slow: mark test as slow to run")
    config.addinivalue_line("markers", "no_docker: mark test as failing in docker")


def pytest_collection_modifyitems(config, items):
    if config.getoption("--runslow"):
        # --runslow given in cli: do not skip slow tests
        return
    skip_slow = pytest.mark.skip(reason="need --runslow option to run")
    for item in items:
        if "slow" in item.keywords:
            item.add_marker(skip_slow)

    if config.getoption("--nodocker"):
        # --nodocker given in cli: skip tests that fail in docker
        skip_docker = pytest.mark.skip(reason="skipping tests that fail in docker")
        for item in items:
            if "no_docker" in item.keywords:
                item.add_marker(skip_docker)
