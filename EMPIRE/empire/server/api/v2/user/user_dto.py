from datetime import datetime

from pydantic import BaseModel

from empire.server.api.v2.shared_dto import (
    DownloadDescription,
    domain_to_dto_download_description,
)


def domain_to_dto_user(user):
    if user.avatar:
        download_description = domain_to_dto_download_description(user.avatar)
    else:
        download_description = None
    return User(
        id=user.id,
        username=user.username,
        enabled=user.enabled,
        is_admin=user.admin,
        created_at=user.created_at,
        updated_at=user.updated_at,
        avatar=download_description,
    )


class User(BaseModel):
    id: int
    username: str
    enabled: bool
    is_admin: bool
    avatar: DownloadDescription | None = None
    created_at: datetime
    updated_at: datetime


class Users(BaseModel):
    records: list[User]


class UserPostRequest(BaseModel):
    username: str
    password: str
    is_admin: bool


class UserUpdateRequest(BaseModel):
    username: str
    enabled: bool
    is_admin: bool


class UserUpdatePasswordRequest(BaseModel):
    password: str
