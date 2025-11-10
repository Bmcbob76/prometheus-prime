from fastapi import Depends

import empire.server.common.empire
from empire.server.api.api_router import APIRouter
from empire.server.api.jwt_auth import get_current_active_user
from empire.server.api.v2.meta.meta_dto import EmpireVersion
from empire.server.api.v2.shared_dto import BadRequestResponse, NotFoundResponse

router = APIRouter(
    prefix="/api/v2/meta",
    tags=["meta"],
    responses={
        404: {"description": "Not found", "model": NotFoundResponse},
        400: {"description": "Bad request", "model": BadRequestResponse},
    },
    dependencies=[Depends(get_current_active_user)],
)


@router.get(
    "/version",
    response_model=EmpireVersion,
)
async def read_empire_version():
    return {"version": empire.server.common.empire.VERSION.split(" ")[0]}
