import typing
from typing import Any

from pydantic import BaseModel

from empire.server.api.v2.shared_dto import (
    Author,
    CustomOptionSchema,
    coerced_dict,
    to_value_type,
)

if typing.TYPE_CHECKING:
    from empire.server.core.plugin_service import PluginHolder


def domain_to_dto_plugin(plugin: "PluginHolder", db):
    loaded_plugin = plugin.loaded_plugin
    db_plugin = plugin.db_plugin
    info = db_plugin.info
    execution_options = None
    settings_options = None

    if loaded_plugin:
        execution_options = {
            x[0]: {
                "description": x[1]["Description"],
                "required": x[1]["Required"],
                "value": x[1]["Value"],
                "strict": x[1]["Strict"],
                "suggested_values": x[1]["SuggestedValues"],
                "value_type": to_value_type(x[1]["Value"], x[1].get("Type")),
                "depends_on": (
                    x[1]["Depends_on"] if x[1]["Depends_on"] is not None else []
                ),
                "internal": x[1]["Internal"] if x[1]["Internal"] is not None else False,
            }
            for x in loaded_plugin.execution_options.items()
        }

        settings_options = {
            x[0]: {
                "description": x[1]["Description"],
                "editable": x[1].get("Editable", True),
                "required": x[1]["Required"],
                "value": x[1]["Value"],
                "strict": x[1]["Strict"],
                "suggested_values": x[1]["SuggestedValues"],
                "value_type": to_value_type(x[1]["Value"], x[1].get("Type")),
                "depends_on": (
                    x[1]["Depends_on"] if x[1]["Depends_on"] is not None else []
                ),
                "internal": x[1]["Internal"] if x[1]["Internal"] is not None else False,
            }
            for x in loaded_plugin.settings_options.items()
        }

    return Plugin(
        id=db_plugin.id,
        name=info.name,
        authors=[a.model_dump() for a in info.authors],
        readme=info.readme,
        techniques=info.techniques,
        software=info.software,
        execution_options=execution_options,
        settings_options=settings_options,
        current_settings=loaded_plugin.current_settings(db) if loaded_plugin else None,
        enabled=loaded_plugin.enabled if loaded_plugin else False,
        loaded=loaded_plugin is not None,
        execution_enabled=loaded_plugin.execution_enabled if loaded_plugin else False,
        python_deps=info.python_deps,
    )


class Plugin(BaseModel):
    id: str
    name: str
    authors: list[Author]
    readme: str | None = ""
    techniques: list[str] = []
    software: str | None = None
    execution_options: dict[str, CustomOptionSchema] | None = None
    settings_options: dict[str, CustomOptionSchema] | None = None
    current_settings: dict[str, Any] | None = None
    enabled: bool
    loaded: bool = False
    execution_enabled: bool = False
    python_deps: list[str] | None = []


class Plugins(BaseModel):
    records: list[Plugin]


class PluginExecutePostRequest(BaseModel):
    options: coerced_dict


class PluginExecuteResponse(BaseModel):
    detail: str = ""


class PluginUpdateRequest(BaseModel):
    enabled: bool


class PluginInstallGitRequest(BaseModel):
    url: str
    ref: str | None = None
    subdirectory: str | None = None


class PluginInstallTarRequest(BaseModel):
    url: str
    subdirectory: str | None = None
