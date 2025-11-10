import base64
import shlex
from binascii import hexlify
from struct import calcsize, pack


def process_arguments(format_string, arguments):
    """
    Processes a single string of arguments into a list and passes
    them to bof_pack. Handles quoted strings properly. Returns hexlified packed data.
    """
    arg_list = shlex.split(arguments)
    packed_data = bof_pack(format_string, arg_list)

    return base64.b64encode(hexlify(packed_data)).decode("utf-8")


def bof_pack(fstring: str, args: list):
    """
    Packs arguments in a format suitable for sending to a beacon-object-file (BOF).
    """
    buffer = b""
    size = 0

    def addshort(short):
        nonlocal buffer, size
        buffer += pack("<h", int(short))
        size += 2

    def addint(dint):
        nonlocal buffer, size
        buffer += pack("<i", int(dint))
        size += 4

    def addstr(s):
        nonlocal buffer, size
        s = s.encode("utf-8") if isinstance(s, str) else s
        fmt = f"<L{len(s) + 1}s"
        buffer += pack(fmt, len(s) + 1, s)
        size += calcsize(fmt)

    def addWstr(s):
        nonlocal buffer, size
        s = s.encode("utf-16_le") if isinstance(s, str) else s
        fmt = f"<L{len(s) + 2}s"
        buffer += pack(fmt, len(s) + 2, s)
        size += calcsize(fmt)

    def addbinary(b):
        nonlocal buffer, size
        fmt = f"<L{len(b) + 1}s"
        buffer += pack(fmt, len(b) + 1, b)
        size += calcsize(fmt)

    if len(fstring) != len(args):
        raise ValueError(
            f"Format string length must match arguments: {len(fstring)} != {len(args)}"
        )

    for i, c in enumerate(fstring):
        if c == "b":
            with open(args[i], "rb") as fd:
                addbinary(fd.read())
        elif c == "c":
            addbinary(args[i])
        elif c == "i":
            addint(args[i])
        elif c == "s":
            addshort(args[i])
        elif c == "z":
            addstr(args[i])
        elif c == "Z":
            addWstr(args[i])
        else:
            raise ValueError(f"Invalid format character '{c}' in position {i}.")

    return pack("<L", size) + buffer
