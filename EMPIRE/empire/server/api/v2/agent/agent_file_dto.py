# needed for self referencing
# https://pydantic-docs.helpmanual.io/usage/postponed_annotations/#self-referencing-models
from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic import BaseModel, ConfigDict

from empire.server.api.v2.shared_dto import (
    DownloadDescription,
    domain_to_dto_download_description,
)

if TYPE_CHECKING:
    from empire.server.core.db import models


def domain_to_dto_file(file: models.AgentFile, children: list[models.AgentFile]):
    return AgentFile(
        id=file.id,
        session_id=file.session_id,
        name=file.name,
        path=file.path,
        is_file=file.is_file,
        parent_id=file.parent_id,
        downloads=[domain_to_dto_download_description(x) for x in file.downloads],
        children=[domain_to_dto_file(c, []) for c in children],
    )


class AgentFile(BaseModel):
    id: int
    session_id: str
    name: str
    path: str
    is_file: bool
    parent_id: int | None = None
    downloads: list[DownloadDescription]
    children: list[AgentFile] = []
    model_config = ConfigDict(from_attributes=True)


AgentFile.model_rebuild()
