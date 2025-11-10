import typing

from sqlalchemy.orm import Session

from empire.server.core.module_models import EmpireModuleOption


def safe_cast(option: typing.Any, expected_option_type: type) -> typing.Any | None:
    try:
        if expected_option_type is bool:
            return option.lower() in ["true", "1"]
        return expected_option_type(option)
    except ValueError:
        return None


def convert_module_options(options: list[EmpireModuleOption]) -> dict:
    """
    Since modules options are typed classes vs listeners/stagers/etc which are dicts, this function
    converts the options to dicts so they can use the same validation logic in validate_options.
    """
    converted_options = {}

    for option in options:
        if option.internal:
            continue

        converted_options[option.name] = {
            "Description": option.description,
            "Required": option.required,
            "Value": option.value,
            "SuggestedValues": option.suggested_values,
            "Strict": option.strict,
            "Type": option.type,
            "NameInCode": option.name_in_code,
            "Internal": option.internal,
            "DependsOn": option.depends_on,
        }

    return converted_options


def validate_options(  # noqa: PLR0912
    instance_options: dict, params: dict, db: Session, download_service
) -> tuple[dict | None, str | None]:
    """
    Compares the options passed in (params) to the options defined in the
    class (instance). If any options are invalid, returns a Tuple of
    (None, error_message). If all options are valid, returns a Tuple of
    (options, None).

    Will also attempt to cast the options to the correct type using safe_cast.
    Options of type "file" are not validated.
    If an option has "Editable" set to False, it will be skipped (Only applies to
    plugins for now).
    """
    options = {}
    params = params.copy()

    for instance_key, option_meta in instance_options.items():
        if option_meta.get("Internal", False):
            continue

        if not evaluate_dependencies(option_meta, params):
            continue

        if option_meta.get("Editable", True) is False:
            continue

        if instance_key not in params and option_meta["Value"] not in ["", None]:
            params[instance_key] = option_meta["Value"]

        if is_option_required(option_meta, params) and (
            instance_key not in params
            or params[instance_key] == ""
            or params[instance_key] is None
        ):
            return None, f"required option missing: {instance_key}"

        if _lower_default(option_meta.get("Type")) == "file":
            if params.get(instance_key):
                db_download = download_service.get_by_id(db, params[instance_key])
                if not db_download:
                    return (
                        None,
                        f"File not found for '{instance_key}' id {params[instance_key]}",
                    )

                options[instance_key] = db_download
            else:
                options[instance_key] = ""
            continue

        if option_meta.get("Strict") and params.get(
            instance_key, ""
        ) not in option_meta.get("SuggestedValues"):
            return (
                None,
                f"{instance_key} must be set to one of the suggested values.",
            )

        casted, err = _safe_cast_option(
            instance_key, params.get(instance_key, ""), option_meta
        )
        if err:
            return None, err

        if option_meta.get("NameInCode"):
            options[option_meta["NameInCode"]] = casted
        else:
            options[instance_key] = casted

    return options, None


def is_option_required(option_meta: dict, params: dict) -> bool:
    """
    Check if an option should be validated based on its `depends_on` configuration.
    This will return True if the option's dependencies are met.
    """
    dependencies = option_meta.get("DependsOn", [])

    if not dependencies:
        # If there are no dependencies, treat the option as required based on the 'Required' field
        return option_meta.get("Required", False)

    # If there are dependencies, check if all are satisfied
    for dependency in dependencies:
        dependent_option = dependency["name"]
        required_values = dependency["values"]

        # Check if the dependent option's value matches any of the required values
        if params.get(dependent_option) not in required_values:
            return (
                False  # If any dependency is not satisfied, the option is not required
            )

    # If all dependencies are satisfied, return True
    return True


def evaluate_dependencies(option, params):
    """
    Evaluate the depends_on conditions for a given option.
    :param option: The option being validated.
    :param params: The current parameters provided by the user.
    :return: Boolean indicating if the dependencies are met.
    """
    if "depends_on" not in option:
        return True

    for dependency in option["depends_on"]:
        dependent_option = dependency["name"]
        if dependent_option not in params:
            return False
        if (
            "values" in dependency
            and params[dependent_option] not in dependency["values"]
        ):
            return False

    return True


def set_options(instance, options: dict):
    """
    Sets the options for the listener/stager instance.
    """
    for option_name, option_value in options.items():
        instance.options[option_name]["Value"] = option_value


def _lower_default(x):
    return "" if x is None else x.lower()


def get_file_options(db, download_service, options, params):
    files = {}

    for option_name, _option_meta in filter(
        lambda x: _lower_default(x[1].get("Type")) == "file", options.items()
    ):
        db_download = download_service.get_by_id(db, params[option_name])
        if not db_download:
            return (
                None,
                f"File not found for '{option_name}' id {params[option_name]}",
            )

        files[option_name] = db_download

    return files, None


def _parse_type(type_str: str = "", value: str = ""):  # noqa: PLR0911
    if not type_str:
        return type(value)

    if type_str.lower() in ["int", "integer"]:
        return int
    if type_str.lower() in ["bool", "boolean"]:
        return bool
    if type_str.lower() in ["str", "string"]:
        return str
    if type_str.lower() == "float":
        return float
    if type_str.lower() == "file":
        return "file"
    return None


def _safe_cast_option(
    param_name, param_value, option_meta
) -> tuple[typing.Any, str | None]:
    option_type = type(param_value)
    if option_meta.get("Type") is not None and isinstance(
        option_meta.get("Type"), type
    ):
        expected_option_type = option_meta.get("Type")
    else:
        expected_option_type = _parse_type(
            option_meta.get("Type"), option_meta.get("Value")
        )
    casted = safe_cast(param_value, expected_option_type)
    if casted is None:
        return (
            None,
            f"incorrect type for option {param_name}. Expected {expected_option_type} but got {option_type}",
        )
    return casted, None
