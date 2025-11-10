import base64
import logging
import subprocess
import tempfile
import zlib
from pathlib import Path

from empire.server.common.helpers import random_string
from empire.server.core.config.config_manager import empire_config
from empire.server.core.config.data_manager import sync_empire_compiler
from empire.server.core.exceptions import ModuleExecutionException

log = logging.getLogger(__name__)


class DotnetCompiler:
    def __init__(self, install_path):
        self.install_path = install_path
        self.compiler_dir = (
            sync_empire_compiler(empire_config.empire_compiler) / "EmpireCompiler"
        )

    def compile_task(
        self, compiler_yaml, task_name, dot_net_version="net40", confuse=False
    ) -> Path:
        random_task_name = f"{task_name}_{random_string(6)}.exe"

        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            output_path = temp_file.name
            args = [
                "./EmpireCompiler",
                "--output",
                output_path,
                "--dotnet-version",
                dot_net_version,
                "--yaml",
                base64.b64encode(compiler_yaml.encode("UTF-8")).decode("UTF-8"),
            ]

            if confuse:
                args.extend(["--confuse"])

            result = subprocess.run(
                args,
                capture_output=True,
                text=True,
                check=False,
                cwd=self.compiler_dir,
            )

            if result.returncode != 0:
                raise ModuleExecutionException(
                    f"EmpireCompiler execution failed with error: {result.stderr.strip()}"
                )

            if "Final Task Path:" not in result.stdout.strip():
                log.error(result.stdout)
                raise ModuleExecutionException("Module compile failed")

            exe_location = Path(output_path)
            exe_location = exe_location.rename(exe_location.with_name(random_task_name))
            compiled_location = exe_location.with_suffix(".compiled")

            data_bytes = exe_location.read_bytes()
            encoded_data = zlib.compress(data_bytes, level=-1)[2:-4]
            compiled_location.write_bytes(encoded_data)

            return compiled_location

    def compile_stager(
        self, compiler_yaml, task_name, dot_net_version="net40", confuse=False
    ) -> Path:
        random_task_name = f"{task_name}_{random_string(4)}.exe"

        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            output_path = temp_file.name
            args = [
                "./EmpireCompiler",
                "--output",
                output_path,
                "--dotnet-version",
                dot_net_version,
                "--yaml",
                base64.b64encode(compiler_yaml.encode("UTF-8")).decode("UTF-8"),
            ]

            if confuse:
                args.extend(["--confuse"])

            result = subprocess.run(
                args,
                capture_output=True,
                text=True,
                check=False,
                cwd=self.compiler_dir,
            )

            if result.returncode != 0:
                raise ModuleExecutionException(
                    f"EmpireCompiler execution failed with error: {result.stderr.strip()}"
                )

            if "Final Task Path:" not in result.stdout.strip():
                log.error(result.stdout)
                raise ModuleExecutionException("Stager compile failed")

        exe_location = Path(output_path)
        return exe_location.rename(exe_location.with_name(random_task_name))
