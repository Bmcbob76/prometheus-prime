import shutil
import subprocess
import tempfile
from pathlib import Path

from empire.server.common.helpers import random_string
from empire.server.utils.file_util import run_as_user


class GitOperationException(Exception):
    pass


def clone_git_repo(
    git_url: str, ref: str | None = None, directory: Path | None = None
) -> Path:
    """
    Clones a git repository to a directory and checks out a specific ref if provided.

    :param git_url: The git URL to clone
    :param directory: The directory to clone the git repository to. If None, a temporary directory is used.
    :param ref: The ref to check out
    :return: The directory the git repository was cloned to
    """
    tmp_dir = Path(tempfile.gettempdir()) / random_string(5)

    try:
        run_as_user(["git", "clone", git_url, tmp_dir])
    except subprocess.CalledProcessError:
        raise GitOperationException(
            f"Failed to clone git repository: {git_url}"
        ) from None

    if ref:
        try:
            run_as_user(["git", "checkout", ref], cwd=tmp_dir)
        except subprocess.CalledProcessError:
            raise GitOperationException(f"Failed to check out ref {ref}") from None

    if directory:
        shutil.copytree(tmp_dir, directory)

    return directory or tmp_dir
