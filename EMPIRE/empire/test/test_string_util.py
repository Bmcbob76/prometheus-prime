import pytest

from empire.server.utils.string_util import is_valid_session_id, slugify


@pytest.mark.parametrize(
    ("session_id", "expected"),
    [
        ("ABCDEFGH", True),
        ("12345678", True),
        ("ABCDEF1H", True),
        ("A1B2C3D4", True),
        ("ABCDEFG", False),
        ("ABCDEFGHI", False),
        ("ABCD_EFG", False),
        ("       ", False),
        ("", False),
        (12345678, False),
        (None, False),
        ("./../../", False),
    ],
)
def test_is_valid_session_id(session_id, expected):
    assert is_valid_session_id(session_id) == expected, (
        f"Test failed for session_id: {session_id}"
    )


def test_slugify():
    assert (
        slugify("this/has invalid_characters-in\tstring")
        == "this_has_invalid_characters_in_string"
    )
