import shutil
import subprocess
import tarfile
import typing
from contextlib import contextmanager
from pathlib import Path

import pytest
from starlette.status import (
    HTTP_200_OK,
    HTTP_204_NO_CONTENT,
    HTTP_400_BAD_REQUEST,
    HTTP_404_NOT_FOUND,
    HTTP_500_INTERNAL_SERVER_ERROR,
)

from empire.server.core.exceptions import (
    PluginExecutionException,
    PluginValidationException,
)

if typing.TYPE_CHECKING:
    from empire.server.core.plugin_service import PluginService


@contextmanager
def patch_plugin_execute(main, plugin_name, execute_func):
    old_execute = main.pluginsv2.loaded_plugins[plugin_name].execute
    main.pluginsv2.loaded_plugins[plugin_name].execute = execute_func
    yield
    main.pluginsv2.loaded_plugins[plugin_name].execute = old_execute


@contextmanager
def patch_plugin_on_start(main, plugin_name, on_start_func):
    old_on_start = main.pluginsv2.loaded_plugins[plugin_name].on_start
    main.pluginsv2.loaded_plugins[plugin_name].on_start = on_start_func
    yield
    main.pluginsv2.loaded_plugins[plugin_name].on_start = old_on_start


def test_get_plugin_not_found(client, admin_auth_header):
    response = client.get("/api/v2/plugins/some_plugin", headers=admin_auth_header)

    assert response.status_code == HTTP_404_NOT_FOUND
    assert response.json()["detail"] == "Plugin not found for id some_plugin"


def test_get_plugin(client, admin_auth_header):
    response = client.get("/api/v2/plugins/basic_reporting", headers=admin_auth_header)

    assert response.status_code == HTTP_200_OK
    assert response.json()["id"] == "basic_reporting"


def test_get_plugins(client, admin_auth_header):
    response = client.get("/api/v2/plugins", headers=admin_auth_header)

    assert response.status_code == HTTP_200_OK
    assert len(response.json()["records"]) > 0


def test_execute_plugin_not_found(client, admin_auth_header):
    response = client.post(
        "/api/v2/plugins/some_plugin/execute", headers=admin_auth_header
    )

    assert response.status_code == HTTP_404_NOT_FOUND
    assert response.json()["detail"] == "Plugin not found for id some_plugin"


def test_execute_plugin_validation_failed(client, admin_auth_header):
    response = client.post(
        "/api/v2/plugins/basic_reporting/execute",
        json={
            "options": {
                "report": "",
            }
        },
        headers=admin_auth_header,
    )

    assert response.status_code == HTTP_400_BAD_REQUEST
    assert response.json()["detail"] == "required option missing: report"


def test_execute_plugin_raises_exception(client, admin_auth_header, main):
    with patch_plugin_execute(main, "basic_reporting", lambda x, **kwargs: 1 / 0):
        response = client.post(
            "/api/v2/plugins/basic_reporting/execute",
            json={"options": {}},
            headers=admin_auth_header,
        )

    assert response.status_code == HTTP_500_INTERNAL_SERVER_ERROR
    assert response.json()["detail"] == "division by zero"


def test_execute_plugin_returns_false(client, admin_auth_header, main):
    with patch_plugin_execute(main, "basic_reporting", lambda x, **kwargs: False):
        response = client.post(
            "/api/v2/plugins/basic_reporting/execute",
            json={"options": {}},
            headers=admin_auth_header,
        )

    assert response.status_code == HTTP_500_INTERNAL_SERVER_ERROR
    assert response.json()["detail"] == "internal plugin error"


def test_execute_plugin_returns_false_with_string(client, admin_auth_header, main):
    with patch_plugin_execute(
        main, "basic_reporting", lambda x, **kwargs: (False, "This is the message")
    ):
        response = client.post(
            "/api/v2/plugins/basic_reporting/execute",
            json={"options": {}},
            headers=admin_auth_header,
        )

    assert response.status_code == HTTP_500_INTERNAL_SERVER_ERROR
    assert response.json()["detail"] == "This is the message"


def test_execute_plugin_returns_string(client, admin_auth_header, main):
    with patch_plugin_execute(
        main, "basic_reporting", lambda x, **kwargs: "Successful Execution"
    ):
        response = client.post(
            "/api/v2/plugins/basic_reporting/execute",
            json={"options": {}},
            headers=admin_auth_header,
        )

    assert response.status_code == HTTP_200_OK
    assert response.json() == {"detail": "Successful Execution"}


def test_execute_plugin_returns_true(client, admin_auth_header, main):
    with patch_plugin_execute(main, "basic_reporting", lambda x, **kwargs: True):
        response = client.post(
            "/api/v2/plugins/basic_reporting/execute",
            json={"options": {}},
            headers=admin_auth_header,
        )

    assert response.status_code == HTTP_200_OK
    assert response.json() == {"detail": "Plugin executed successfully"}


def test_execute_plugin_returns_true_with_string(client, admin_auth_header, main):
    # Since the second value represents an err, the first value is ignored and this is treated as an error.
    with patch_plugin_execute(
        main, "basic_reporting", lambda x, **kwargs: (True, "This is the message")
    ):
        response = client.post(
            "/api/v2/plugins/basic_reporting/execute",
            json={"options": {}},
            headers=admin_auth_header,
        )

    assert response.status_code == HTTP_500_INTERNAL_SERVER_ERROR
    assert response.json() == {"detail": "This is the message"}


def test_execute_plugin_raises_plugin_validation_exception(
    client, admin_auth_header, main
):
    def raise_():
        raise PluginValidationException("This is the message")

    with patch_plugin_execute(main, "basic_reporting", lambda x, **kwargs: raise_()):
        response = client.post(
            "/api/v2/plugins/basic_reporting/execute",
            json={"options": {}},
            headers=admin_auth_header,
        )

    assert response.status_code == HTTP_400_BAD_REQUEST
    assert response.json() == {"detail": "This is the message"}


def test_execute_plugin_raises_plugin_execution_exception(
    client, admin_auth_header, main
):
    def raise_():
        raise PluginExecutionException("This is the message")

    with patch_plugin_execute(main, "basic_reporting", lambda x, **kwargs: raise_()):
        response = client.post(
            "/api/v2/plugins/basic_reporting/execute",
            json={"options": {}},
            headers=admin_auth_header,
        )

    assert response.status_code == HTTP_500_INTERNAL_SERVER_ERROR
    assert response.json() == {"detail": "This is the message"}


def test_execute_plugin_returns_none(client, admin_auth_header, main):
    with patch_plugin_execute(main, "basic_reporting", lambda x, **kwargs: None):
        response = client.post(
            "/api/v2/plugins/basic_reporting/execute",
            json={"options": {}},
            headers=admin_auth_header,
        )

    assert response.status_code == HTTP_200_OK
    assert response.json() == {"detail": "Plugin executed successfully"}


def test_reload_plugins(client, admin_auth_header):
    # Get initial list of plugins
    initial_response = client.get("/api/v2/plugins", headers=admin_auth_header)
    initial_plugins = initial_response.json()["records"]

    # Call the reload plugins endpoint
    response = client.post("/api/v2/plugins/reload", headers=admin_auth_header)
    assert response.status_code == HTTP_204_NO_CONTENT

    # Get the list of plugins after reloading
    final_response = client.get("/api/v2/plugins", headers=admin_auth_header)
    final_plugins = final_response.json()["records"]

    # The initial and final list of plugins should be the same after reload
    assert len(initial_plugins) == len(final_plugins)


def test_toggle_plugin_enabled(client, admin_auth_header, main, session_local):
    response = client.get("/api/v2/plugins/basic_reporting", headers=admin_auth_header)
    assert response.json()["enabled"] is True

    # Execute should work
    response = client.post(
        "/api/v2/plugins/basic_reporting/execute",
        json={"options": {}},
        headers=admin_auth_header,
    )
    assert response.status_code == HTTP_200_OK

    # Stop the plugin
    response = client.put(
        "/api/v2/plugins/basic_reporting",
        json={"enabled": False},
        headers=admin_auth_header,
    )
    assert response.status_code == HTTP_200_OK

    # Execute should fail
    response = client.post(
        "/api/v2/plugins/basic_reporting/execute",
        json={"options": {}},
        headers=admin_auth_header,
    )
    assert response.status_code == HTTP_400_BAD_REQUEST

    # Start the plugin
    response = client.put(
        "/api/v2/plugins/basic_reporting",
        json={"enabled": True},
        headers=admin_auth_header,
    )
    assert response.status_code == HTTP_200_OK

    response = client.get("/api/v2/plugins/basic_reporting", headers=admin_auth_header)
    assert response.json()["enabled"] is True


def test_toggle_plugin_enabled_causes_exception(client, admin_auth_header, main):
    def _raise(db):
        raise PluginExecutionException("Error Test Test")

    with patch_plugin_on_start(main, "basic_reporting", _raise):
        client.put(
            "/api/v2/plugins/basic_reporting",
            json={"enabled": False},
            headers=admin_auth_header,
        )

        response = client.put(
            "/api/v2/plugins/basic_reporting",
            json={"enabled": True},
            headers=admin_auth_header,
        )

        assert response.status_code == HTTP_500_INTERNAL_SERVER_ERROR
        assert response.json() == {"detail": "Error Test Test"}

        response = client.get(
            "/api/v2/plugins/basic_reporting", headers=admin_auth_header
        )
        assert response.json()["enabled"] is False

    response = client.put(
        "/api/v2/plugins/basic_reporting",
        json={"enabled": True},
        headers=admin_auth_header,
    )
    assert response.status_code == HTTP_200_OK


def test_plugin_settings(client, admin_auth_header, main):
    response = client.get("/api/v2/plugins/example_2", headers=admin_auth_header)
    assert response.status_code == HTTP_200_OK

    assert response.json()["settings_options"] == {
        "SomeEditableSetting": {
            "editable": True,
            "description": "Edit This",
            "required": True,
            "value": "",
            "strict": False,
            "suggested_values": [],
            "value_type": "STRING",
            "internal": False,
            "depends_on": [],
        },
        "SomeNonEditableSetting": {
            "editable": False,
            "description": "This is displayed to users, but can't be changed via the API",
            "required": True,
            "value": "Hello World",
            "strict": False,
            "suggested_values": [],
            "value_type": "STRING",
            "internal": False,
            "depends_on": [],
        },
    }

    assert response.json()["current_settings"] == {
        "SomeEditableSetting": "",
        "SomeNonEditableSetting": "Hello World",
    }

    # Validation failure
    response = client.put(
        "/api/v2/plugins/example_2/settings",
        json={},  # Missing required fields
        headers=admin_auth_header,
    )

    assert response.status_code == HTTP_400_BAD_REQUEST
    assert response.json() == {"detail": "required option missing: SomeEditableSetting"}

    # Update the settings
    response = client.put(
        "/api/v2/plugins/example_2/settings",
        # The only field that is required and missing a default
        json={"SomeEditableSetting": "0.0.0.0"},
        headers=admin_auth_header,
    )

    assert response.status_code == HTTP_200_OK

    response = client.get("/api/v2/plugins/example_2", headers=admin_auth_header)

    # Settings should be updated
    assert response.status_code == HTTP_200_OK
    assert response.json()["current_settings"] == {
        "SomeEditableSetting": "0.0.0.0",
        "SomeNonEditableSetting": "Hello World",
    }


def test_plugin_settings_non_editable(client, admin_auth_header, main, session_local):
    with session_local() as db:
        # Check the initial value of the non-editable field
        internal_plugin = main.pluginsv2.loaded_plugins["example_2"]
        assert internal_plugin.current_settings(db) == {
            "SomeEditableSetting": "0.0.0.0",
            "SomeNonEditableSetting": "Hello World",
        }

        response = client.get("/api/v2/plugins/example_2", headers=admin_auth_header)
        assert response.status_code == HTTP_200_OK
        assert (
            response.json()["settings_options"]
            .get("SomeNonEditableSetting")
            .get("editable")
            is False
        )
        assert response.json()["current_settings"] == {
            "SomeEditableSetting": "0.0.0.0",
            "SomeNonEditableSetting": "Hello World",
        }

        # Trying to edit the field won't result in an error,
        # but it also won't do anything.
        response = client.put(
            "/api/v2/plugins/example_2/settings",
            json={
                "SomeEditableSetting": "0.0.0.0",
                "SomeNonEditableSetting": "new value",
            },
            headers=admin_auth_header,
        )
        assert response.status_code == HTTP_200_OK

        response = client.get("/api/v2/plugins/example_2", headers=admin_auth_header)
        assert response.status_code == HTTP_200_OK
        assert response.json()["current_settings"] == {
            "SomeEditableSetting": "0.0.0.0",
            "SomeNonEditableSetting": "Hello World",
        }


def test_plugin_state_internal(client, admin_auth_header, main, session_local):
    with session_local() as db:
        response = client.get("/api/v2/plugins/example_2", headers=admin_auth_header)
        assert response.status_code == HTTP_200_OK
        assert response.json()["settings_options"].get("SomeInternalSetting") is None

        internal_plugin = main.pluginsv2.loaded_plugins["example_2"]
        assert internal_plugin.current_internal_state(db) == {
            "SomeInternalSetting": "internal_state_value"
        }


def test_plugin_disabled_execution(client, admin_auth_header, main):
    internal_plugin = main.pluginsv2.loaded_plugins["basic_reporting"]
    internal_plugin.execution_enabled = False

    response = client.post(
        "/api/v2/plugins/basic_reporting/execute",
        json={"options": {}},
        headers=admin_auth_header,
    )

    # Assert that the plugin execution is disabled and returns the expected response
    assert response.status_code == HTTP_400_BAD_REQUEST
    assert response.json() == {"detail": "Plugin execution is disabled"}


def _git_commands(cwd, commands: list[list[str]]):
    for c in commands:
        subprocess.run(["git", *c], cwd=cwd, check=True)


@pytest.fixture
def foo_plugin():
    """Creates a FooPlugin directory with a git repository and a tar for testing git plugin installation."""
    template_path = Path(__file__).parent / "plugin_install/FooPluginTemplate"
    foo_plugin_path = template_path.parent / "FooPlugin"

    shutil.rmtree(foo_plugin_path, ignore_errors=True)
    shutil.copytree(template_path, foo_plugin_path)

    with tarfile.open(str(foo_plugin_path.parent / "FooPlugin.tar"), "w") as tar:
        tar.add(str(foo_plugin_path), arcname="FooPlugin")

    # Verify the tar archive was created
    if not (foo_plugin_path.parent / "FooPlugin.tar").exists():
        raise FileNotFoundError(f"Tar archive {foo_plugin_path} was not created")

    _git_commands(
        foo_plugin_path,
        [
            ["init"],
            ["reset", "--soft"],
            ["commit", "--allow-empty", "-m", "Initial commit"],
            ["checkout", "-b", "6.0"],
            ["add", "."],
            ["commit", "-m", "6.0 file structure"],
            ["checkout", "master"],
        ],
    )

    yield foo_plugin_path

    shutil.rmtree(foo_plugin_path, ignore_errors=True)
    (foo_plugin_path.parent / "FooPlugin.tar").unlink(missing_ok=True)


@pytest.fixture(scope="session")
def plugin_service(main) -> "PluginService":
    return main.pluginsv2


@pytest.fixture
def _cleanup_foo_plugin(plugin_service, session_local, models):
    plugin_service.loaded_plugins.pop("foo", None)
    shutil.rmtree(plugin_service.marketplace_path / "foo", ignore_errors=True)
    with session_local.begin() as db:
        db.query(models.Plugin).filter(models.Plugin.name == "foo").delete()

    yield

    plugin_service.loaded_plugins.pop("foo", None)
    shutil.rmtree(plugin_service.marketplace_path / "foo", ignore_errors=True)
    with session_local.begin() as db:
        db.query(models.Plugin).filter(models.Plugin.name == "foo").delete()


@pytest.mark.no_docker
@pytest.mark.usefixtures("_cleanup_foo_plugin")
def test_install_plugin_git_invalid(
    client,
    admin_auth_header,
    main,
    foo_plugin,
):
    invalid_url = "file:///some/invalid/git/url"
    response = client.post(
        "/api/v2/plugins/install/git",
        json={
            "url": invalid_url,
            "ref": "master",
        },
        headers=admin_auth_header,
    )

    assert response.status_code == HTTP_400_BAD_REQUEST
    assert response.json() == {
        "detail": f"Failed to install plugin from git: Failed to clone git repository: {invalid_url}"
    }

    response = client.post(
        "/api/v2/plugins/install/git",
        json={
            "url": "file://" + str(foo_plugin.absolute()),
            "ref": "master",
        },
        headers=admin_auth_header,
    )

    assert response.status_code == HTTP_400_BAD_REQUEST
    assert response.json() == {"detail": "plugin.yaml not found"}


@pytest.mark.no_docker
@pytest.mark.usefixtures("_cleanup_foo_plugin")
def test_install_plugin_with_python_deps(
    client, admin_auth_header, main, foo_plugin, session_local
):
    # Add a twilio import to the plugin so that it triggers the import error
    _git_commands(foo_plugin, [["checkout", "6.0"]])
    foo_py = (foo_plugin / "foo.py").read_text()
    foo_py_lines = foo_py.split("\n")
    last_import_index = max(
        i for i, line in enumerate(foo_py_lines) if line.startswith("import ")
    )
    foo_py_lines.insert(last_import_index + 1, "import twilio")
    (foo_plugin / "foo.py").write_text("\n".join(foo_py_lines))
    _git_commands(foo_plugin, [["add", "."], ["commit", "-m", "Add twilio import"]])

    response = client.post(
        "/api/v2/plugins/install/git",
        json={
            "url": "file://" + str(foo_plugin.absolute()),
            "ref": "6.0",
        },
        headers=admin_auth_header,
    )

    assert response.status_code == HTTP_200_OK

    response = client.get("/api/v2/plugins/foo", headers=admin_auth_header)
    assert response.status_code == HTTP_200_OK
    assert response.json()["loaded"] is False

    assert main.pluginsv2.loaded_plugins.get("foo") is None
    with session_local.begin() as db:
        assert main.pluginsv2.get_by_id(db, "foo") is not None


@pytest.mark.no_docker
@pytest.mark.usefixtures("_cleanup_foo_plugin")
def test_install_plugin_git(client, admin_auth_header, main, foo_plugin):
    response = client.post(
        "/api/v2/plugins/install/git",
        json={
            "url": "file://" + str(foo_plugin.absolute()),
            "ref": "6.0",
        },
        headers=admin_auth_header,
    )

    assert response.status_code == HTTP_200_OK
    assert main.pluginsv2.loaded_plugins.get("foo") is not None

    response = client.get("/api/v2/plugins/foo", headers=admin_auth_header)
    assert response.status_code == HTTP_200_OK
    assert response.json()["python_deps"] == ["requests>=2.25.1", "twilio"]

    # Test duplicate install
    response = client.post(
        "/api/v2/plugins/install/git",
        json={
            "url": "file://" + str(foo_plugin.absolute()),
            "ref": "6.0",
        },
        headers=admin_auth_header,
    )

    assert response.status_code == HTTP_400_BAD_REQUEST
    assert response.json() == {"detail": "Plugin already exists"}


@pytest.mark.no_docker
@pytest.mark.usefixtures("_cleanup_foo_plugin")
def test_install_plugin_git_subdirectory(
    client,
    admin_auth_header,
    main,
    foo_plugin,
):
    subdir = foo_plugin / "sub"
    _git_commands(foo_plugin, [["checkout", "6.0"]])
    subdir.mkdir()
    for f in foo_plugin.iterdir():
        if f.name not in ("sub", ".git"):
            f.rename(subdir / f.name)

    assert (subdir / "plugin.yaml").exists()

    _git_commands(
        foo_plugin,
        [
            ["add", "."],
            ["commit", "-m", "6.0 subdirectory"],
            ["checkout", "master"],
        ],
    )

    response = client.post(
        "/api/v2/plugins/install/git",
        json={
            "url": "file://" + str(foo_plugin.absolute()),
            "ref": "6.0",
            "subdirectory": "sub",
        },
        headers=admin_auth_header,
    )

    assert response.status_code == HTTP_200_OK
    assert main.pluginsv2.loaded_plugins.get("foo") is not None


@pytest.mark.no_docker
@pytest.mark.usefixtures("_cleanup_foo_plugin")
def test_install_plugin_tar_invalid(
    client,
    admin_auth_header,
    main,
    foo_plugin,
):
    invalid_url = "file:///some/invalid/tar/url"
    response = client.post(
        "/api/v2/plugins/install/tar",
        json={
            "url": invalid_url,
        },
        headers=admin_auth_header,
    )

    assert response.status_code == HTTP_400_BAD_REQUEST
    assert response.json() == {
        "detail": "Failed to download plugin: [Errno 2] No such file or directory: '/some/invalid/tar/url'"
    }

    # Create an empty tar
    empty_tar = foo_plugin.parent / "Empty.tar"
    with tarfile.open(str(empty_tar), "w"):
        pass

    response = client.post(
        "/api/v2/plugins/install/tar",
        json={
            "url": "file://" + str(empty_tar.absolute()),
        },
        headers=admin_auth_header,
    )
    empty_tar.unlink(missing_ok=True)

    assert response.status_code == HTTP_400_BAD_REQUEST
    assert response.json() == {"detail": "plugin.yaml not found"}


@pytest.mark.no_docker
@pytest.mark.usefixtures("_cleanup_foo_plugin")
def test_install_plugin_tar_subirectory(client, admin_auth_header, main, foo_plugin):
    tar_path = foo_plugin.parent / "FooPlugin.tar"
    response = client.post(
        "/api/v2/plugins/install/tar",
        json={
            "url": f"file://{tar_path.absolute()}",
            "subdirectory": "FooPlugin",
        },
        headers=admin_auth_header,
    )

    assert response.status_code == HTTP_200_OK
    assert main.pluginsv2.loaded_plugins.get("foo") is not None

    # Test duplicate install
    response = client.post(
        "/api/v2/plugins/install/tar",
        json={
            "url": f"file://{tar_path.absolute()}",
            "subdirectory": "FooPlugin",
        },
        headers=admin_auth_header,
    )

    assert response.status_code == HTTP_400_BAD_REQUEST
    assert response.json() == {"detail": "Plugin already exists"}
