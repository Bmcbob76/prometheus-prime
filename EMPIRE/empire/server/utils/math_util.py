import numbers


def old_div(a, b):
    """
    Equivalent to ``a / b`` on Python 2 without ``from __future__ import
    division``.
    """
    if isinstance(a, numbers.Integral) and isinstance(b, numbers.Integral):
        return a // b
    return a / b
