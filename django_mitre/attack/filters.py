import django_filtering as filtering

from ..core.filters import MitreFilterSet
from . import models


class MitreAttackFilterSet(MitreFilterSet):
    collection = filtering.Filter(
        filtering.ChoiceLookup("exact", label="is"),
        default_lookup="exact",
        label="Collection",
    )

    class Meta:
        abstract = True


class GroupFilterSet(MitreAttackFilterSet):
    class Meta:
        model = models.Group


class SoftwareFilterSet(MitreAttackFilterSet):
    class Meta:
        model = models.Software


class TechniqueFilterSet(MitreAttackFilterSet):
    tactic = filtering.Filter(
        filtering.ChoiceLookup("exact", label="is"),
        default_lookup="exact",
        label="Tactic",
    )

    class Meta:
        model = models.Technique
