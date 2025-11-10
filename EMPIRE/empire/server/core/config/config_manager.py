import logging
import os
import shutil
import sys
from pathlib import Path
from typing import Annotated

import netaddr
import yaml
from netaddr.core import AddrFormatError
from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

log = logging.getLogger(__name__)


class EmpireBaseModel(BaseModel):
    @field_validator("*")
    @classmethod
    def set_path(cls, v):
        if isinstance(v, Path):
            if v.expanduser().is_absolute():
                return v.expanduser().resolve()
            return DATA_DIR / v
        return v


class ApiConfig(EmpireBaseModel):
    ip: str = "0.0.0.0"
    port: int = 1337
    secure: bool = False


class SubmodulesConfig(EmpireBaseModel):
    auto_update: bool = True


class StarkillerConfig(EmpireBaseModel):
    enabled: bool = True
    repo: str = "bc-security/starkiller"
    ref: str = "main"


class EmpireCompilerConfig(EmpireBaseModel):
    archive: str = ""
    # This is only used if you are using a self-compiled
    # version that is not already tarred and published.
    directory: str | None = None


class DatabaseDefaultObfuscationConfig(EmpireBaseModel):
    language: str = "powershell"
    enabled: bool = False
    command: str = r"Token\All\1"
    module: str = "invoke-obfuscation"
    preobfuscatable: bool = True


def valid_ip(v: str):
    try:
        if "-" in v:
            start, end = v.split("-")
            netaddr.IPRange(start, end)
        elif "/" in v:
            netaddr.IPNetwork(v)
        else:
            netaddr.IPAddress(v)

        return v
    except AddrFormatError as e:
        raise ValueError(
            f"Invalid IP address {v}. Must be a valid IP Address, Range, or CIDR."
        ) from e


class DatabaseDefaultsConfig(EmpireBaseModel):
    staging_key: str = ""
    username: str = "empireadmin"
    password: str = "password123"
    obfuscation: list[DatabaseDefaultObfuscationConfig] = []
    keyword_obfuscation: list[str] = []
    ip_allow_list: list[Annotated[str, AfterValidator(valid_ip)]] = []
    ip_deny_list: list[Annotated[str, AfterValidator(valid_ip)]] = []


class SQLiteDatabaseConfig(EmpireBaseModel):
    location: Path = Path("empire.db")


class MySQLDatabaseConfig(EmpireBaseModel):
    url: str = "localhost:3306"
    username: str = ""
    password: str = ""
    database_name: str = "empire"


class DatabaseConfig(EmpireBaseModel):
    use: str = "sqlite"
    sqlite: SQLiteDatabaseConfig
    mysql: MySQLDatabaseConfig
    defaults: DatabaseDefaultsConfig

    def __getitem__(self, key):
        return getattr(self, key)


class DirectoriesConfig(EmpireBaseModel):
    downloads: Path = Path("downloads")


class LoggingConfig(EmpireBaseModel):
    level: str = "INFO"
    simple_console: bool = True


class LastTaskConfig(EmpireBaseModel):
    enabled: bool = False
    file: Path = Path("debug/last_task.txt")


class DebugConfig(EmpireBaseModel):
    last_task: LastTaskConfig


class PluginAutoExecuteConfig(EmpireBaseModel):
    enabled: bool = False
    options: dict[str, str] = {}


class PluginConfig(EmpireBaseModel):
    auto_start: bool | None = None
    auto_execute: PluginAutoExecuteConfig | None = None


class PluginRegistryConfig(EmpireBaseModel):
    name: str
    location: Path | None = None
    url: str | None = None
    git_url: str | None = None
    ref: str | None = None
    file: str | None = None

    @model_validator(mode="before")
    @classmethod
    def validate_location_or_url_or_git_url(cls, values):
        if not (values.get("location") or values.get("url") or values.get("git_url")):
            raise ValueError("Either location, url, or git_url must be set")
        return values


class PluginMarketplaceConfig(EmpireBaseModel):
    registries: list[PluginRegistryConfig] = []


class EmpireConfig(EmpireBaseModel):
    supress_self_cert_warning: bool = Field(default=True)
    api: ApiConfig = ApiConfig()
    empire_compiler: EmpireCompilerConfig = EmpireCompilerConfig()
    starkiller: StarkillerConfig = StarkillerConfig()
    submodules: SubmodulesConfig = SubmodulesConfig()
    database: DatabaseConfig = DatabaseConfig(
        sqlite=SQLiteDatabaseConfig(),
        mysql=MySQLDatabaseConfig(),
        defaults=DatabaseDefaultsConfig(),
    )
    plugins: dict[str, PluginConfig] = {}
    plugin_marketplace: PluginMarketplaceConfig = PluginMarketplaceConfig()
    directories: DirectoriesConfig = DirectoriesConfig()
    logging: LoggingConfig = LoggingConfig()
    debug: DebugConfig = DebugConfig(last_task=LastTaskConfig())

    model_config = ConfigDict(extra="allow")

    def __init__(self, config_dict: dict | None = None):
        if config_dict is None:
            config_dict = {}
        if not isinstance(config_dict, dict):
            raise ValueError("config_dict must be a dictionary")

        super().__init__(**config_dict)
        # For backwards compatibility
        self.yaml = config_dict

    def __getitem__(self, key):
        return getattr(self, key)


def set_yaml(location: str):
    location = Path(location).expanduser().resolve()
    try:
        with location.open() as stream:
            return yaml.safe_load(stream)
    except yaml.YAMLError as exc:
        log.warning(exc)
    except FileNotFoundError as exc:
        log.warning(exc)


DEFAULT_CONFIG = Path("empire/server/config.yaml")

if os.environ.get("TEST_MODE"):
    CONFIG_DIR = Path.home() / ".config" / "empire-test"
    DATA_DIR = Path.home() / ".local" / "share" / "empire-test"
    shutil.rmtree(CONFIG_DIR, ignore_errors=True)
    shutil.rmtree(DATA_DIR, ignore_errors=True)

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    test_registry_1 = Path("empire/test/test_registry_1.yaml")
    test_registry_2 = Path("empire/test/test_registry_2.yaml")
    shutil.copy(test_registry_1, DATA_DIR / "test_registry_1.yaml")
    shutil.copy(test_registry_2, DATA_DIR / "test_registry_2.yaml")
else:
    CONFIG_DIR = Path.home() / ".config" / "empire"
    DATA_DIR = Path.home() / ".local" / "share" / "empire"

CONFIG_PATH = CONFIG_DIR / "config.yaml"
CONFIG_DIR.mkdir(parents=True, exist_ok=True)
DATA_DIR.mkdir(parents=True, exist_ok=True)

if not CONFIG_PATH.exists():
    shutil.copy(DEFAULT_CONFIG, CONFIG_PATH)
    log.info(f"Copied {DEFAULT_CONFIG} to {CONFIG_PATH}")


config_dict = EmpireConfig().model_dump()
if "--config" in sys.argv:
    location = sys.argv[sys.argv.index("--config") + 1]
    log.info(f"Loading config from {location}")
    loaded_config = set_yaml(location)
    if loaded_config:
        config_dict = loaded_config
elif CONFIG_PATH.exists():
    log.info("Loading default config")
    loaded_config = set_yaml(str(CONFIG_PATH))
    if loaded_config:
        config_dict = loaded_config

empire_config = EmpireConfig(config_dict)
