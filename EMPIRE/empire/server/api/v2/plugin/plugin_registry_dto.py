from pydantic import BaseModel

from empire.server.api.v2.shared_dto import Author


class MarketPlaceEntryVersionResponse(BaseModel):
    name: str
    git_url: str | None = None
    tar_url: str | None = None
    ref: str | None = None
    subdirectory: str | None = None


class MarketplaceEntryRegistryResponse(BaseModel):
    name: str
    registry: str
    homepage_url: str | None = None
    source_url: str | None = None
    authors: list[Author]
    versions: list[MarketPlaceEntryVersionResponse]
    description: str


class MarketplaceEntryResponse(BaseModel):
    name: str
    registries: dict[str, MarketplaceEntryRegistryResponse]
    installed: bool = False
    installed_version: str | None = None


class MarketplaceResponse(BaseModel):
    records: list[MarketplaceEntryResponse]


class PluginInstallRequest(BaseModel):
    name: str
    version: str
    registry: str
