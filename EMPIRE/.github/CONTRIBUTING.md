# How To Contribute

Contributions are more than welcome! The more people who contribute to the project the better Empire will be for everyone. Below are a few guidelines for submitting contributions.


## Creating Github Issues

Please first review the existing Empire issues to see if the error was resolved with a fix in the development branch or if we chose not to fix the error for some reason.

The more information you provide in a Github issue the easier it will be for us to track down and fix the problem:

* Please provide the version of Empire you are using.
* Please provide the OS and Python versions that you are using.
* Please describe the expected behavior and the encountered error.
  * The more detail the better!
  * Include any actions taken just prior to the error.
  * Please post a screenshot of the error, a link to a Pastebin dump of the error, or embedded text of the error.
* Any additional information.

## Documentation

Documentation is the `docs/` directory and syncs with [GitBook](https://bc-security.gitbook.io/empire-wiki/).
The documentation is written in [Markdown](https://www.markdownguide.org/basic-syntax/).
Please submit your documentation with your code changes if applicable.
The `main` branch in `BC-SECURITY/Empire` automatically syncs.


## Submitting Code

### Where should I branch my code?

* Submit pull requests to the [main branch](https://github.com/BC-SECURITY/Empire/tree/main). After testing, changes will be merged to `main`.
  * Sponsors Repo: Submit pull requests to `private-main` for most cases. `sponsors-main` for sponsor specific changes, `kali-main` for kali specific changes.


### Modules

* Depending on what you're working on, base your module on [powershell_template.py](https://github.com/BC-SECURITY/Empire/blob/master/empire/server/modules/powershell_template.py) or [python_template.py](https://github.com/BC-SECURITY/Empire/blob/master/empire/server/modules/python_template.py). **Note** that for some modules you may need to massage the output to get it into a nicely displayable text format with [Out-String](https://github.com/PowerShellEmpire/Empire/blob/0cbdb165a29e4a65ad8dddf03f6f0e36c33a7350/lib/modules/situational_awareness/network/powerview/get_user.py#L111).
* Cite previous work in the **'Comments'** module section.
* If your script.ps1 logic is large, may be reused by multiple modules, or is updated often, consider implementing the logic in the appropriate **data/module_source/*** directory and [pulling the script contents into the module on tasking](https://github.com/PowerShellEmpire/Empire/blob/0cbdb165a29e4a65ad8dddf03f6f0e36c33a7350/lib/modules/situational_awareness/network/powerview/get_user.py#L85-L95).
* Use [approved PowerShell verbs](https://docs.microsoft.com/en-us/powershell/scripting/developer/cmdlet/approved-verbs-for-windows-powershell-commands?view=powershell-7.1) for any functions.
* TEST YOUR MODULE! Be sure to run it from an Empire agent and test Python 3.x functionality before submitting a pull to ensure everything is working correctly.
* For additional guidelines for your PowerShell code itself, check out the [PowerSploit style guide](https://github.com/PowerShellMafia/PowerSploit/blob/master/README.md).
* For more in-depth docs on developing modules, see the [Module Development docs](https://bc-security.gitbook.io/empire-wiki/module-development)

### Code Formatting and Linting

* We are using [astral-sh/ruff](https://github.com/astral-sh/ruff) for linting and formatting.
* After implementing your changes:
    1. run `ruff check . --fix` (or `poetry run ruff check . --fix`).
    2. run `ruff format .` (or `poetry run ruff format .`).
* The repo is also configured to use [pre-commit](https://pre-commit.com/) to automatically format code.
  * Once you have pre-commit installed, you can run `pre-commit install` to install the pre-commit hooks.
  * Then pre-commit will execute ruff automatically before committing.

### Tests

Please write tests for your code! We use [pytest](https://docs.pytest.org/en/latest/) for testing. Tests are located in the `tests/` directory. To run the tests, run `pytest` from the root directory of the project.

For tests that take >20-30 seconds, please add the `@pytest.mark.slow` decorator to the test function. This will allow us to skip the slow tests when running the tests, unless we explicitly want to run them with `pytest --runslow`.

## Upgrading dependencies
Dependencies can be upgraded using [poetry-plugin-up](https://github.com/MousaZeidBaker/poetry-plugin-up).
