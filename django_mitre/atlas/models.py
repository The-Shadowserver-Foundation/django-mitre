import re
from urllib.parse import urljoin

from django.contrib.contenttypes.fields import GenericForeignKey, GenericRelation
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import ImproperlyConfigured
from django.db import models
from django.db.models.signals import pre_save
from django.dispatch import receiver
from django.shortcuts import reverse

from ..core.utils.model import model_url_name


__all__ = (
    "ALL_MODELS",
    "Collection",
    "Matrix",
    "Mitigation",
    "Reference",
    "Tactic",
    "Technique",
)


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


class MitreAtlasManager(models.Manager):
    def get_active(self):
        """
        Filters out the revoked and deprecated records. Not applicable to Mitre Atlas.
        Provides a compatible interface for general use within django-mitre.
        """
        return self.get_queryset()


class DescriptiveMixIn(models.Model):
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    short_description = models.TextField(blank=True, null=True)

    class Meta:
        abstract = True


class Collection(DescriptiveMixIn, models.Model):
    """
    Collection of Mitre Atlas data

    This data point is primarily used as a container for versioning the data.
    """

    uuid = models.UUIDField(unique=True)
    created = models.DateField()
    modified = models.DateField()
    #: CalVer versioning
    version = models.CharField(max_length=8, unique=True)
    #: Internal field so when know when this object was applied/ingested.
    applied = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.name} @ {self.version}"


class BaseMitreAtlasModel(DescriptiveMixIn, models.Model):
    objects = MitreAtlasManager()

    uuid = models.UUIDField()
    mitre_id = models.CharField(max_length=255)
    #: The complete ID is a Mitre ID prefixed with the _framework_ (e.g. 'AML.').
    mitre_id_complete = models.CharField(max_length=255)

    #: Copy of the original data
    mitre_original_data = models.JSONField()
    created = models.DateField()
    modified = models.DateField()

    collection = models.ForeignKey(Collection, on_delete=models.CASCADE)

    # TODO 'attack-reference' if present is a dict {'id': 'XXXXXX', 'URL': 'https://attack.mitre.org/ttttt/xxxxx'}

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

    def _get_mitre_url(self, permalink=False):
        if self.mitre_url_path is None:
            raise ImproperlyConfigured(
                "The model does not define the `mitre_url_path` attribute (e.g. '/tactics/')."
            )
        base_url = "https://atlas.mitre.org/"
        if permalink:
            base_url = urljoin(base_url, f"v/{self.collection.version}/")
        base_url = urljoin(base_url, self.mitre_url_path)
        return urljoin(base_url, self.mitre_id_complete)

    @property
    def mitre_url(self):
        """Canonical external Mitre URL for this object."""
        if self.mitre_url_path is None:
            raise
        base_url = urljoin("https://atlas.mitre.org/", self.mitre_url_path)
        return urljoin(base_url, self.mitre_id_complete)

    @property
    def mitre_permalink_url(self):
        """Canonical external Mitre versioned URL for this object."""
        if self.mitre_url_path is None:
            raise
        base_url = urljoin(
            f"https://atlas.mitre.org/v/{self.collection.version}/", self.mitre_url_path
        )
        return urljoin(base_url, self.mitre_id_complete)

    def get_absolute_url(self):
        return reverse(model_url_name(self, "detail"), kwargs={"slug": self.mitre_id})

    def __str__(self):
        return f"{super().__str__()} - {self.mitre_id}"

    class Meta:
        abstract = True


class Matrix(BaseMitreAtlasModel):
    """
    Matrix in Mitre Atlas

    This is primarily a visual categorization of Tactics
    to relate and contain techniques.
    """

    mitre_url_path = '/matrices/'

    class Meta:
        verbose_name_plural = "matrices"


class Technique(BaseMitreAtlasModel):
    """
    A Technique represents the specific method a adversary uses to accomplish a tactical goal.
    """

    mitre_url_path = '/techniques/'

    #: Mirror of atlas.enums.TechniqueMaturity
    class Maturity(models.TextChoices):
        FEASIBLE = "Feasible"
        DEMONSTRATED = "Demonstrated"
        REALIZED = "Realized"

    #: Mirror of atlas.enums.TechniquePlatformType
    class Platform(models.TextChoices):
        PREDICTIVE = "Predictive AI"
        GENERATIVE = "Generative AI"
        AGENTIC = "Agentic AI"
        ENTERPRISE = "Enterprise"

    platforms = models.JSONField(null=True, blank=True)
    maturity = models.CharField(max_length=12, choices=Maturity)
    attack_reference = models.JSONField(null=True, blank=True)

    # Mitre specific data
    is_subtechnique = models.BooleanField(default=False)
    major_technique = models.ForeignKey(
        "Technique",
        on_delete=models.CASCADE,
        related_name="subtechniques",
        null=True,
        blank=True,
    )


class Tactic(BaseMitreAtlasModel):
    """
    A Tactic represents the adversary's tactical goal
    at a given stage of an attack against an ML system.

    These are siblings of a (singular) Matrix.
    They are a parent (in a multi parent relationship) to Techniques.
    """

    mitre_url_path = '/tactics/'

    techniques = models.ManyToManyField(Technique, blank=True)

    def __str__(self):
        return f"{self.name} ({self.mitre_id}) within {self.collection.name}"


class Mitigation(BaseMitreAtlasModel):
    """
    A Mitigation describes a security concept, tool, or configuration/process change
    that can prevent or reduce the effectiveness of one or more techniques.
    """

    mitre_url_path = '/mitigations/'

    lifecycle_phases = models.JSONField()
    categories = models.JSONField()


class CaseStudy(BaseMitreAtlasModel):
    """
    Case Studies are real-world or realistic incident narratives that document
    actual or simulated attacks against ML systems.
    """

    mitre_url_path = '/studies/'

    #: Mirror of atlas.enums.DateGranularity
    class DateGranularity(models.TextChoices):
        YEAR = "Year"
        MONTH = "Month"
        DAY = "Day"

    type = models.CharField(max_length=255)
    actor = models.CharField(max_length=255)
    target = models.CharField(max_length=255)
    reporter = models.CharField(max_length=255, null=True, blank=True)
    date = models.DateField()
    date_granularity = models.CharField(choices=DateGranularity)


class Reference(BaseMitreAtlasModel):
    """
    Relational reference from a source to a target.
    It typically relates like: <source> <relation-type> <target>.
    For example, "AML.M0019 mitigates AML.T0040"
    """

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


ALL_MODELS = (
    CaseStudy,
    Collection,
    Matrix,
    Mitigation,
    Reference,
    Tactic,
    Technique,
)
