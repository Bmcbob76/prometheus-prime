from empire.server.common.empire import MainMenu
from empire.server.core.module_models import EmpireModule
from empire.server.core.module_service import auto_finalize


class Module:
    @staticmethod
    @auto_finalize
    def generate(
        main_menu: MainMenu,
        module: EmpireModule,
        params: dict,
        obfuscate: bool = False,
        obfuscation_command: str = "",
    ):
        return "Script", "ScriptEnd"
