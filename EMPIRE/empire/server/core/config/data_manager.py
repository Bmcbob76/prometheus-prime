import logging
import platform
import tarfile
from pathlib import Path

import requests

from empire.server.core.config import config_manager
from empire.server.core.config.config_manager import (
    EmpireCompilerConfig,
    StarkillerConfig,
)
from empire.server.utils.git_util import clone_git_repo

log = logging.getLogger(__name__)


def sync_starkiller(starkiller_config: StarkillerConfig):
    starkiller_dir = config_manager.DATA_DIR / "starkiller" / starkiller_config.ref

    if not Path(starkiller_dir).exists():
        log.info("Starkiller: directory not found. Cloning Starkiller")
        clone_git_repo(starkiller_config.repo, starkiller_config.ref, starkiller_dir)

    return starkiller_dir


def sync_empire_compiler(compiler_config: EmpireCompilerConfig):
    os_ = platform.system()
    arch = platform.machine()

    if os_ == "Darwin":
        os_ = "osx"
    elif os_ == "Linux":
        os_ = "linux"
    else:
        log.error(f"Empire Compiler: unsupported OS '{os_}'")
        return None

    if arch == "x86_64":
        arch = "x64"
    elif arch in ["aarch64", "arm64"]:
        arch = "arm64"
    else:
        log.error(f"Empire Compiler: unsupported architecture '{arch}'")
        return None

    name = (
        compiler_config.archive.split("/")[-1]
        .removesuffix(".tgz")
        .replace("{{platform}}", f"{os_}-{arch}")
    )
    compiler_dir = config_manager.DATA_DIR / "empire-compiler"

    if not Path(compiler_dir / name).exists():
        log.info("Empire Compiler: directory not found. Cloning Empire Compiler")

        url = compiler_config.archive.replace("{{platform}}", f"{os_}-{arch}")
        log.info(f"Empire Compiler: fetching and unarchiving {url}")

        with (
            requests.get(url, stream=True) as resp,
            tarfile.open(fileobj=resp.raw, mode="r|gz") as tar,
        ):
            tar.extractall(compiler_dir)

    return compiler_dir / name
