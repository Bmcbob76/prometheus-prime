import typing

from fastapi import UploadFile
from sqlalchemy.orm import Session

from empire.server.core.db import models

if typing.TYPE_CHECKING:
    from empire.server.common.empire import MainMenu
    from empire.server.core.download_service import DownloadService


class UserService:
    def __init__(self, main_menu: "MainMenu"):
        self.main_menu = main_menu
        self.download_service: DownloadService = main_menu.downloadsv2

    @staticmethod
    def get_all(db: Session):
        return db.query(models.User).all()

    @staticmethod
    def get_by_id(db: Session, uid: int) -> models.User:
        return db.query(models.User).filter(models.User.id == uid).first()

    @staticmethod
    def get_by_name(db: Session, name: str):
        return db.query(models.User).filter(models.User.username == name).first()

    def create_user(
        self, db: Session, username: str, hashed_password: str, admin: bool = False
    ):
        db_user = self.get_by_name(db, username)

        if db_user:
            return None, f"A user with name {username} already exists."

        user = models.User(
            username=username,
            hashed_password=hashed_password,
            enabled=True,
            admin=admin,
        )

        db.add(user)
        db.flush()

        return user, None

    def update_user(self, db: Session, db_user: models.User, user_req):
        if user_req.username != db_user.username:
            if not self.get_by_name(db, user_req.username):
                db_user.username = user_req.username
            else:
                return None, f"A user with name {user_req.username} already exists."

        db_user.enabled = user_req.enabled
        db_user.admin = user_req.is_admin

        return db_user, None

    @staticmethod
    def update_user_password(db: Session, db_user: models.User, hashed_password: str):
        db_user.hashed_password = hashed_password
        db.flush()

        return db_user, None

    def update_user_avatar(self, db: Session, db_user: models.User, file: UploadFile):
        download = self.download_service.create_download(db, db_user, file)

        db_user.avatar = download
