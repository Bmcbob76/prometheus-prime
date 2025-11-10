from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from empire.server.core.db import models


class Keyword(BaseModel):
    id: int
    keyword: str
    replacement: str
    created_at: datetime
    updated_at: datetime
    model_config = ConfigDict(from_attributes=True)


class Keywords(BaseModel):
    records: list[Keyword]


class KeywordUpdateRequest(BaseModel):
    keyword: str = Field(min_length=3)
    replacement: str = Field(min_length=3)


class KeywordPostRequest(BaseModel):
    keyword: str = Field(min_length=3)
    replacement: str = Field(min_length=3)


def domain_to_dto_obfuscation_config(obf_conf: models.ObfuscationConfig):
    return ObfuscationConfig(
        language=obf_conf.language,
        enabled=obf_conf.enabled,
        command=obf_conf.command,
        module=obf_conf.module,
        preobfuscatable=obf_conf.preobfuscatable,
    )


class ObfuscationConfig(BaseModel):
    language: str
    enabled: bool
    command: str
    module: str
    preobfuscatable: bool
    model_config = ConfigDict(from_attributes=True)


class ObfuscationConfigs(BaseModel):
    records: list[ObfuscationConfig]


class ObfuscationConfigUpdateRequest(BaseModel):
    enabled: bool
    command: str
    module: str
