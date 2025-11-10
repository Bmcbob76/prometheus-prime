from pydantic import BaseModel


class EmpireVersion(BaseModel):
    version: str
