import argparse

parent_parser = argparse.ArgumentParser()
subparsers = parent_parser.add_subparsers(dest="subparser_name")

server_parser = subparsers.add_parser("server", help="Launch Empire Server")
setup_parser = subparsers.add_parser(
    "setup", help="Setup the data directories for Empire"
)
install_parser = subparsers.add_parser("install", help="Install the Empire framework")
install_parser.add_argument(
    "-y",
    action="store_true",
    help="Automatically say yes to all prompts during installation",
)

# Server Args
general_group = server_parser.add_argument_group("General Options")
general_group.add_argument(
    "-l",
    "--log-level",
    dest="log_level",
    type=str.upper,
    choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
    help="Set the logging level",
)
general_group.add_argument(
    "-d",
    "--debug",
    help="Set the logging level to DEBUG",
    action="store_const",
    dest="log_level",
    const="DEBUG",
    default=None,
)
general_group.add_argument(
    "--reset",
    action="store_true",
    help="Drop and reinitialize the database. Keep config and Starkiller/Empire-Compiler files intact.",
)
general_group.add_argument(
    "--clean",
    action="store_true",
    help="Drop and reinitialize the database. Removes Starkiller/Empire-Compiler files.",
)
general_group.add_argument(
    "-v", "--version", action="store_true", help="Display current Empire version."
)
general_group.add_argument(
    "--config",
    type=str,
    nargs=1,
    help="Specify a config.yaml different from the config.yaml in the empire/server directory.",
)

args = parent_parser.parse_args()

if parent_parser.parse_args().subparser_name is None:
    parent_parser.print_help()
