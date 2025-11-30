import re

from django.contrib.contenttypes.fields import GenericForeignKey, GenericRelation
from django.contrib.contenttypes.models import ContentType
from django.db import models
from django.db.models.signals import pre_save
from django.dispatch import receiver

from ..core.models import MitreIdentifiableMixIn


__all__ = (
    "Collection",
    "Software",
    "Tactic",
    "Technique",
    "Reference",
    "Matrix",
    "ALL_MODELS",
)


class MitreManager(models.Manager):
    def get_active(self):
        """Filters out the revoked and deprecated records"""
        return self.get_queryset().filter(revoked=False, deprecated=False)


class Collection(models.Model):
    """Collection of Mitre Att&ck data

    Uses the custom ``x-mitre-collection`` STIX 2.1 data type.
    This data point is primarily used as a container for versioning the data.

    """

    stix_data_types = ("x-mitre-collection",)
    mitre_stix_identifier = models.CharField(max_length=255, unique=True)
    name = models.CharField(max_length=255)
    description = models.TextField()
    version = models.CharField(max_length=8)
    applied = models.DateTimeField(auto_now_add=True)
    shortname = models.CharField(max_length=16, unique=True)

    def __str__(self):
        return f"{self.name} @ {self.version}"


class BaseModel(models.Model):
    objects = MitreManager()
    mitre_stix_identifier = models.CharField(max_length=255, unique=True)
    mitre_original_data = models.JSONField()
    collection = models.ForeignKey(Collection, on_delete=models.CASCADE)

    created = models.DateTimeField()
    modified = models.DateTimeField()
    deprecated = models.BooleanField(default=False)
    revoked = models.BooleanField(default=False)

    source_refs = GenericRelation(
        "Reference",
        content_type_field="source_ref_content_type",
        object_id_field="source_ref_id",
    )

    target_refs = GenericRelation(
        "Reference",
        content_type_field="target_ref_content_type",
        object_id_field="target_ref_id",
    )

    def __str__(self):
        return f"{self.mitre_stix_identifier}"

    class Meta:
        abstract = True


class DescriptiveMixIn(models.Model):
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    short_description = models.TextField(blank=True, null=True)

    class Meta:
        abstract = True


FIRST_SENTENCE_REGEX = re.compile(r"^[^.!?]*\[[^]]+\]\([^)]*\)[^.!?]*[.!?]|^[^.!?]+[.!?]")


def shorten_description(desc: str) -> str:
    """Shorten a long description to one line."""
    match = FIRST_SENTENCE_REGEX.match(desc)
    if match:
        return match.group(0)


@receiver(pre_save)
def collect_short_description(sender, instance, **kwargs):
    """Handle the assignment of short description from the long description."""
    if isinstance(instance, DescriptiveMixIn) and instance.description:
        instance.short_description = shorten_description(instance.description)


class Software(BaseModel, DescriptiveMixIn, MitreIdentifiableMixIn):
    """Software in Mitre Att&ck and Malware in STIX 2.1

    Uses the ``malware`` and ``tool`` STIX 2.1 data type.

    """

    TOOL = "tool"
    MALWARE = "malware"
    stix_data_types = (
        TOOL,
        MALWARE,
    )
    TYPE_CHOICES = [(TOOL, TOOL.title()), (MALWARE, MALWARE.title())]
    type = models.CharField(
        choices=TYPE_CHOICES,
        max_length=max(*[len(t) for t, _ in TYPE_CHOICES]),
    )
    is_family = models.BooleanField(default=False)
    aliases = models.JSONField(blank=True, null=True)
    platforms = models.JSONField(blank=True, null=True)
    version = models.CharField(max_length=16)
    contributors = models.JSONField(blank=True, null=True)

    class Meta:
        verbose_name = "malware"
        verbose_name_plural = "malware"


class Technique(BaseModel, DescriptiveMixIn, MitreIdentifiableMixIn):
    """Technique in Mitre Att&ck and Attack Pattern in STIX 2.1

    Uses the ``attack-pattern`` STIX 2.1 data type.

    """

    stix_data_types = ("attack-pattern",)
    kill_chain_phases = models.JSONField(blank=True, null=True)
    external_references = models.JSONField()

    # Mitre specific data
    is_subtechnique = models.BooleanField(default=False)
    major_technique = models.ForeignKey(
        "Technique",
        on_delete=models.CASCADE,
        related_name="subtechniques",
        null=True,
        blank=True,
    )
    detection_description = models.TextField(null=True, blank=True)
    platforms = models.JSONField(null=True, blank=True)
    version = models.CharField(max_length=16)
    contributors = models.JSONField(null=True, blank=True)
    permissions_required = models.JSONField(null=True, blank=True)
    system_requirements = models.CharField(null=True, blank=True, max_length=512)
    # The `x_mitre_data_sources` data on the surface would seem
    # to link with DataSources, but more precisely they mostly link
    # with specific DataComponents. However, some of the names
    # in this value do not match with either model.
    # data_sources = models.ManyToManyField('DataSource')
    data_sources = models.JSONField(null=True, blank=True)

    class Meta:
        verbose_name = "behavior"


class Reference(BaseModel):
    """Reference in Mitre Att&ck and Relationship in STIX 2.1

    Uses the ``relationship`` STIX 2.1 data type.

    """

    stix_data_types = ("relationship",)
    description = models.TextField(blank=True, null=True)
    relationship_type = models.CharField(max_length=255)

    # source_ref
    source_ref_id = models.PositiveIntegerField(editable=False)
    source_ref_content_type = models.ForeignKey(
        ContentType, on_delete=models.CASCADE, editable=False, related_name="+"
    )
    source_ref = GenericForeignKey("source_ref_content_type", "source_ref_id")

    # target_ref
    target_ref_id = models.PositiveIntegerField(editable=False)
    target_ref_content_type = models.ForeignKey(
        ContentType, on_delete=models.CASCADE, editable=False, related_name="+"
    )
    target_ref = GenericForeignKey("target_ref_content_type", "target_ref_id")

    def __str__(self):
        return f"'{self.source_ref}' {self.relationship_type} '{self.target_ref}'"


class Matrix(BaseModel, DescriptiveMixIn, MitreIdentifiableMixIn):
    """Matrix in Mitre Att&ck

    Uses the custom ``x-mitre-matrix`` STIX 2.1 data type.
    This is primarily a visual catagorization of Tactics
    to relate and contain techniques.

    """

    stix_data_types = ("x-mitre-matrix",)
    # Used by us in navigation to provide a short url directly to the matrix.
    slug = models.CharField(max_length=64)
    # Used to filter techniques by platform on the the matrix page.
    # This property primarily exists to address query speed.
    # Otherwise we'd need to query techniques by tactics
    # associated with the matrix and then produce a set of platforms.
    platforms = models.JSONField(null=True, blank=True)

    class Meta:
        verbose_name_plural = "matrices"


class Tactic(BaseModel, DescriptiveMixIn, MitreIdentifiableMixIn):
    """Tactic in Mitre Att&ck

    These are siblings of a (singular) Matrix.
    They are one parent (in a multi parent relationship) to Techniques.

    Uses the custom ``x-mitre-tactic`` STIX 2.1 data type.

    """

    stix_data_types = ("x-mitre-tactic",)
    # On creation the matrix may or may not exist.
    # The Matrix' original data contains the relationship.
    matrix = models.ForeignKey(
        Matrix,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
    )
    techniques = models.ManyToManyField(Technique, blank=True)
    # This comes from `x_mitre_shortname`, it is used internally
    # to link Techniques' kill_chain_phases-phase_name to a Tactic.
    # The value is not null or blank on any of the records.
    # shortname is unique per collection.
    shortname = models.CharField(max_length=255, blank=False, null=False)
    # Gives the parent Matrix a way to repeatably order the tactics.
    order_weight = models.IntegerField(default=0, blank=True, null=False)

    class Meta:
        verbose_name = "objective"


ALL_MODELS = (
    Collection,
    Software,
    Tactic,
    Technique,
    Reference,
    Matrix,
)
