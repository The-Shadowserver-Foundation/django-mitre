import re


__all__ = (
    "SOFTWARE_ID_PATTERN",
    "TACTIC_ID_PATTERN",
    "TECHNIQUE_ID_PATTERN",
)

app_label = "mitrembc"

# In known cases, the character case of the mitre identifier does not matter.
# The position of the letters in the identifier are the important part.
# Identifier can therefore be matched with case insensitivity (i.e. `re.I`).
# However, they are written for case exact matching in view url registration,
# because we don't absolutely know that MITRE won't change to a character
# case-sensitive identifier scheme.
MATRIX_ID_PATTERN    = (
    f"{app_label}.matrix",
    re.compile(r"(?P<slug>[-a-z0-9]+)", re.I),
)
SOFTWARE_ID_PATTERN  = (
    f"{app_label}.software",
    re.compile(r"(?P<slug>X[0-9]+)", re.I),
)
TACTIC_ID_PATTERN    = (
    f"{app_label}.tactic",
    re.compile(r"(?P<slug>(OB|OC){1}[0-9]+)", re.I),
)
TECHNIQUE_ID_PATTERN = (
    f"{app_label}.technique",
    re.compile(r"(?P<slug>[BCEF]{1}[.0-9m]+)", re.I),
)

MATCHABLE_MODEL_PATTERNS = (
    SOFTWARE_ID_PATTERN,
    TACTIC_ID_PATTERN,
    TECHNIQUE_ID_PATTERN,
)
