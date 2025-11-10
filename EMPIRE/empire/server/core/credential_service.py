import typing

from sqlalchemy import and_, or_
from sqlalchemy.orm import Session

from empire.server.api.v2.credential.credential_dto import CredentialPostRequest
from empire.server.core.db import models

if typing.TYPE_CHECKING:
    from empire.server.common.empire import MainMenu


class CredentialService:
    def __init__(self, main_menu: "MainMenu"):
        self.main_menu = main_menu

    @staticmethod
    def get_all(
        db: Session,
        search: str | None = None,
        credtype: str | None = None,
        tags: list[str] | None = None,
    ):
        query = db.query(models.Credential)

        if search:
            query = query.filter(
                or_(
                    models.Credential.domain.like(f"%{search}%"),
                    models.Credential.username.like(f"%{search}%"),
                    models.Credential.password.like(f"%{search}%"),
                    models.Credential.host.like(f"%{search}%"),
                )
            )

        if tags:
            tags_split = [tag.split(":", 1) for tag in tags]
            query = query.join(models.Credential.tags).filter(
                and_(
                    models.Tag.name.in_([tag[0] for tag in tags_split]),
                    models.Tag.value.in_([tag[1] for tag in tags_split]),
                )
            )

        if credtype:
            query = query.filter(models.Credential.credtype == credtype)

        return query.all()

    @staticmethod
    def get_by_id(db: Session, uid: int) -> models.Credential | None:
        return db.query(models.Credential).filter(models.Credential.id == uid).first()

    @staticmethod
    def delete_credential(db: Session, credential: models.Credential):
        db.delete(credential)

    @staticmethod
    def check_duplicate_credential(db, credential_dto) -> bool:
        """
        Using IntegrityError and depending on the db invalidates the whole
        transaction, so instead we'll check it manually.
        """
        found = (
            db.query(models.Credential)
            .filter(
                and_(
                    models.Credential.credtype == credential_dto.credtype,
                    models.Credential.domain == credential_dto.domain,
                    models.Credential.username == credential_dto.username,
                    models.Credential.password == credential_dto.password,
                )
            )
            .first()
        )

        return found is not None

    def create_credential(self, db: Session, credential_dto: CredentialPostRequest):
        dupe = self.check_duplicate_credential(db, credential_dto)

        if dupe:
            return None, "Credential not created. Duplicate detected."

        credential = models.Credential(**credential_dto.model_dump())

        db.add(credential)
        db.flush()

        return credential, None

    def update_credential(
        self, db: Session, db_credential: models.Credential, credential_req
    ):
        if self.check_duplicate_credential(db, credential_req):
            return None, "Credential not updated. Duplicate detected."

        db_credential.credtype = credential_req.credtype
        db_credential.domain = credential_req.domain
        db_credential.username = credential_req.username
        db_credential.password = credential_req.password
        db_credential.host = credential_req.host
        db_credential.os = credential_req.os
        db_credential.sid = credential_req.sid
        db_credential.notes = credential_req.notes

        db.flush()

        return db_credential, None
