import typing

from sqlalchemy import and_
from sqlalchemy.orm import Session

from empire.server.core.db import models

if typing.TYPE_CHECKING:
    from empire.server.common.empire import MainMenu


class HostProcessService:
    def __init__(self, main_menu: "MainMenu"):
        self.main_menu = main_menu

    @staticmethod
    def get_processes_for_host(db: Session, db_host: models.Host):
        return (
            db.query(models.HostProcess)
            .filter(models.HostProcess.host_id == db_host.id)
            .all()
        )

    @staticmethod
    def get_process_for_host(db: Session, db_host: models.Host, uid: int):
        return (
            db.query(models.HostProcess)
            .filter(
                and_(
                    models.HostProcess.process_id == uid,
                    models.HostProcess.host_id == db_host.id,
                )
            )
            .first()
        )
