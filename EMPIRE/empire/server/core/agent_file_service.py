import typing

from sqlalchemy import and_
from sqlalchemy.orm import Session

from empire.server.core.db import models

if typing.TYPE_CHECKING:
    from empire.server.common.empire import MainMenu


class AgentFileService:
    def __init__(self, main_menu: "MainMenu"):
        self.main_menu = main_menu

    @staticmethod
    def get_file(
        db: Session, agent_id: str, uid: int
    ) -> tuple[models.AgentFile, list[models.AgentFile]] | None:
        found = (
            db.query(models.AgentFile)
            .filter(
                and_(
                    models.AgentFile.session_id == agent_id, models.AgentFile.id == uid
                )
            )
            .first()
        )

        if not found:
            return None

        children = (
            db.query(models.AgentFile)
            .filter(
                and_(
                    models.AgentFile.session_id == agent_id,
                    models.AgentFile.parent_id == found.id,
                )
            )
            .all()
        )

        return found, children

    @staticmethod
    def get_file_by_path(
        db: Session, agent_id: str, path: str
    ) -> tuple[models.AgentFile, list[models.AgentFile]] | None:
        found = (
            db.query(models.AgentFile)
            .filter(
                and_(
                    models.AgentFile.session_id == agent_id,
                    models.AgentFile.path == path,
                )
            )
            .first()
        )

        if not found:
            return None

        children = (
            db.query(models.AgentFile)
            .filter(
                and_(
                    models.AgentFile.session_id == agent_id,
                    models.AgentFile.parent_id == found.id,
                )
            )
            .all()
        )

        return found, children
