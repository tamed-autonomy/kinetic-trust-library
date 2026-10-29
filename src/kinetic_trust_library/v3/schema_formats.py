"""Installed schema formats, independent of jsonschema optional extras."""
from kinetic_trust_library.errors import ValidationError
from kinetic_trust_library.models._uri import validate_absolute_uri


def installed_format_checker():
    from jsonschema import FormatChecker
    checker=FormatChecker()
    @checker.checks("uri")
    def absolute_uri(value):
        if type(value) is not str:
            return True  # JSON Schema applies this format only to strings.
        try:
            validate_absolute_uri(value,name="schema URI")
        except ValidationError:
            return False
        return True
    return checker
