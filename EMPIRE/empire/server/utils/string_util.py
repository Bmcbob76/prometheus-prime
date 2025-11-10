import random
import re
import string

SESSION_ID_PATTERN = re.compile(r"^[A-Z0-9]{8}$")
SLUGIFY_PATTERN = re.compile(r"[/_\-\s]")


def is_valid_session_id(session_id):
    if not isinstance(session_id, str):
        return False
    return SESSION_ID_PATTERN.match(session_id.strip()) is not None


def slugify(s: str):
    return SLUGIFY_PATTERN.sub("_", s).lower()


def get_random_string(length=-1, charset=string.ascii_letters):
    """
    Returns a random string of "length" characters.
    If no length is specified, resulting string is in between 6 and 15 characters.
    A character set can be specified, defaulting to just alpha letters.
    """
    if length == -1:
        length = random.randrange(6, 16)
    return "".join(random.choice(charset) for x in range(length))
