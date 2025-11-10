from typing import Annotated

from fastapi import Depends
from sqlalchemy.orm import Session

from empire.server.common.empire import MainMenu
from empire.server.core.db.base import SessionLocal


def get_db():
    with SessionLocal.begin() as db:
        yield db


def get_main() -> MainMenu:
    from empire.server.server import main

    return main


CurrentSession = Annotated[Session, Depends(get_db)]
AppCtx = Annotated[MainMenu, Depends(get_main)]
