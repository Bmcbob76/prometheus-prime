import typing

from sqlalchemy.orm import Session

from empire.server.core.db import models

if typing.TYPE_CHECKING:
    from empire.server.common.empire import MainMenu


class HostService:
    def __init__(self, main_menu: "MainMenu"):
        self.main_menu = main_menu

    @staticmethod
    def get_all(db: Session):
        return db.query(models.Host).all()

    @staticmethod
    def get_by_id(db: Session, uid: int):
        return db.query(models.Host).filter(models.Host.id == uid).first()
