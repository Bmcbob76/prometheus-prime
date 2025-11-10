from fastapi import Depends, HTTPException
from starlette.responses import Response

from empire.server.api.api_router import APIRouter
from empire.server.api.jwt_auth import (
    get_current_active_admin_user,
    get_current_active_user,
)
from empire.server.api.v2.ip.ip_dto import IP, IpPostRequest, Ips, domain_to_dto_ip
from empire.server.api.v2.shared_dependencies import AppCtx, CurrentSession
from empire.server.api.v2.shared_dto import BadRequestResponse, NotFoundResponse
from empire.server.core.db import models
from empire.server.core.db.models import IpList
from empire.server.core.ip_service import IpService


def get_ip_service(main: AppCtx) -> IpService:
    return main.ipsv2


router = APIRouter(
    prefix="/api/v2/ips",
    tags=["ips"],
    responses={
        404: {"description": "Not found", "model": NotFoundResponse},
        400: {"description": "Bad request", "model": BadRequestResponse},
    },
    dependencies=[Depends(get_current_active_user)],
)


async def get_ip(
    uid: int, db: CurrentSession, ip_service: IpService = Depends(get_ip_service)
):
    ip = ip_service.get_by_id(db, uid)

    if ip:
        return ip

    raise HTTPException(status_code=404, detail=f"Ip not found for id {uid}")


@router.get("/{uid}", response_model=IP)
async def read_ip(uid: int, db_ip: models.IP = Depends(get_ip)):
    return domain_to_dto_ip(db_ip)


@router.get("/", response_model=Ips)
async def read_ips(
    db: CurrentSession,
    ip_list: IpList = None,
    ip_service: IpService = Depends(get_ip_service),
):
    ips = [domain_to_dto_ip(x) for x in ip_service.get_all(db, ip_list)]

    return {"records": ips}


@router.post(
    "/",
    response_model=IP,
    status_code=201,
    dependencies=[Depends(get_current_active_admin_user)],
)
async def create_ip(
    ip: IpPostRequest,
    db: CurrentSession,
    ip_service: IpService = Depends(get_ip_service),
):
    db_ip = ip_service.create_ip(db, ip.ip_address, ip.description, ip.list)
    return domain_to_dto_ip(db_ip)


@router.delete(
    "/{uid}",
    response_class=Response,
    status_code=204,
    dependencies=[Depends(get_current_active_admin_user)],
)
async def delete_ip(
    uid: int,
    db: CurrentSession,
    db_ip: models.IP = Depends(get_ip),
    ip_service: IpService = Depends(get_ip_service),
):
    ip_service.delete_ip(db, db_ip)
