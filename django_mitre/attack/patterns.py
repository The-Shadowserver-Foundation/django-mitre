"""
A set of MITRE identifier patterns.

These patterns uniquely indentify objects by MITRE ID using a character prefix.

This package uses these patterns to create url paths, search by identifier,
rewrite urls in content description, etc.
"""
import re


__all__ = (
    "DATASOURCE_ID_PATTERN",
    "GROUP_ID_PATTERN",
    "MATRIX_ID_PATTERN",
    "MITIGATION_ID_PATTERN",
    "SOFTWARE_ID_PATTERN",
    "TACTIC_ID_PATTERN",
    "TECHNIQUE_ID_PATTERN",
)


app_label = "mitreattack"

# In known cases, the character case of the mitre identifier does not matter.
# The position of the letters in the identifier are the important part.
# Identifier can therefore be matched with case insensitivity (i.e. `re.I`).
# However, they are written for case exact matching in view url registration,
# because we don't absolutely know that MITRE won't change to a character
# case-sensitive identifier scheme.
CAMPAIGN_ID_PATTERN = (
    f"{app_label}.campaign",
    re.compile(r"(?P<slug>C[0-9]+)", re.I),
)
DATASOURCE_ID_PATTERN = (
    f"{app_label}.datasource",
    re.compile(r"(?P<slug>DS[0-9]+)", re.I),
)
GROUP_ID_PATTERN = (
    f"{app_label}.group",
    re.compile(r"(?P<slug>G[0-9]+)", re.I),
)
MATRIX_ID_PATTERN = (
    f"{app_label}.matrix",
    re.compile(r"(?P<slug>[-a-z0-9]+)", re.I),
)
MITIGATION_ID_PATTERN = (
    f"{app_label}.mitigation",
    re.compile(r"(?P<slug>M[0-9]+)", re.I),
)
SOFTWARE_ID_PATTERN = (
    f"{app_label}.software",
    re.compile(r"(?P<slug>S[0-9]+)", re.I),
)
TACTIC_ID_PATTERN = (
    f"{app_label}.tactic",
    re.compile(r"(?P<slug>TA[0-9]+)", re.I),
)
TECHNIQUE_ID_PATTERN = (
    f"{app_label}.technique",
    re.compile(r"(?P<slug>T[.0-9]+)", re.I),
)

MATCHABLE_MODEL_PATTERNS = (
    CAMPAIGN_ID_PATTERN,
    DATASOURCE_ID_PATTERN,
    GROUP_ID_PATTERN,
    MITIGATION_ID_PATTERN,
    SOFTWARE_ID_PATTERN,
    TACTIC_ID_PATTERN,
    TECHNIQUE_ID_PATTERN,
)
