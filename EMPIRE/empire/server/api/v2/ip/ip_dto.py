from datetime import datetime
from typing import Annotated

from pydantic import AfterValidator, BaseModel

from empire.server.core.config.config_manager import valid_ip
from empire.server.core.db.models import IpList


def domain_to_dto_ip(ip):
    return IP(
        id=ip.id,
        ip_address=ip.ip_address,
        list=ip.list,
        description=ip.description,
        created_at=ip.created_at,
        updated_at=ip.updated_at,
    )


class IpPostRequest(BaseModel):
    ip_address: Annotated[str, AfterValidator(valid_ip)]
    description: str | None = None
    list: IpList


class IP(BaseModel):
    id: int
    ip_address: str
    list: IpList
    description: str | None
    created_at: datetime
    updated_at: datetime


class Ips(BaseModel):
    records: list[IP]
