from pydantic import BaseModel


def domain_to_dto_host(host):
    return Host(
        id=host.id,
        name=host.name,
        internal_ip=host.internal_ip,
    )


class Host(BaseModel):
    id: int
    name: str
    internal_ip: str


class Hosts(BaseModel):
    records: list[Host]
