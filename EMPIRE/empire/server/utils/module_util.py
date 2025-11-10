import warnings

from empire.server.common import helpers


def handle_error_message(
    msg: str = "", print_to_server: bool = True
) -> tuple[str | None, str]:
    """
    Given a reason for a module execution error, print to server and return the message as a tuple back to
    the modules.py handler to send to the client
    :param msg: the msg to print
    :param print_to_server: whether the msg should print to the server
    :return: tuple of None, str
    """
    warnings.warn(
        "handle_error_message is deprecated. raise ModuleValidationException or ModuleExecutionException instead."
        "https://bc-security.gitbook.io/empire-wiki/module-development/powershell-modules#custom-generate",
        DeprecationWarning,
        stacklevel=2,
    )
    if print_to_server:
        print(helpers.color(msg))
    return None, msg


def handle_validate_message(
    msg: str = "", print_to_server: bool = True
) -> tuple[bool, str]:
    """
    Given a reason for a module execution error, print to server and return the message as a tuple back to
    the modules.py handler to send to the client
    :param msg: the msg to print
    :param print_to_server: whether the msg should print to the server
    :return: tuple of None, str
    """
    if print_to_server:
        print(helpers.color(msg))
    return False, msg
