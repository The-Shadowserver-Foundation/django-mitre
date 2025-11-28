import re

from django.db import models
from django.shortcuts import reverse

from .utils import model_url_name


class MitreIdentifiableMixIn(models.Model):
    # Note, there are records that have the same mitre_id,
    # but different a different stix id.
    # When querying by mitre_id, you should order by descending 'modified'
    # and use the first result. For example,
    # `Group.objects.filter(mitre_id='G0058').order_by('-modified').first()`
    mitre_id = models.CharField(max_length=255)
    mitre_url = models.URLField()

    # The mitre ID pattern is used in URL resolution as well as identifier searches.
    # The mitre ID pattern is a regular expression that can be used to identify
    # a specific piece of content or a classification of mitre content
    # (e.g. T1108 or G1108).
    # The pattern must have a `slug` named grouping (e.g. "(?P<slug>G[0-9]+)").
    mitre_id_pattern: re.Pattern

    def get_absolute_url(self):
        return reverse(model_url_name(self, "detail"), kwargs={"slug": self.mitre_id})

    def __str__(self):
        return f"{super().__str__()} - {self.mitre_id}"

    class Meta:
        abstract = True
