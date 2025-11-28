import re

from django.http import HttpResponseBadRequest
from django.shortcuts import redirect
from django.urls import reverse

from ..core.utils.model import model_url_name
from ..core.utils.prefetch import prefetch_nested_techniques
from ..core.views.base import BaseDetailView
from . import models
from .utils import get_model_by_id


def redirect_by_id(request, mitre_id):
    model = get_model_by_id(mitre_id)
    if model is None:
        return HttpResponseBadRequest("No model found for this id scheme")
    else:
        #: Adjust the identifier to its canonical form.
        mitre_id = re.sub("^([a-z]{1,2})", lambda m: m.group(0).upper(), mitre_id)
        return redirect(reverse(model_url_name(model, "detail"), args=[mitre_id]))


class TechniqueDetailView(BaseDetailView):
    model = models.Technique
    fields = ["name", "short_description"]
    slug_field = "mitre_id"


class SoftwareDetailView(BaseDetailView):
    model = models.Software
    fields = ["name", "short_description"]
    slug_field = "mitre_id"


class TacticDetailView(BaseDetailView):
    model = models.Tactic
    fields = ["name", "short_description"]
    slug_field = "mitre_id"


class MatrixIndexView(BaseDetailView):
    model = models.Matrix
    fields = ["name", "short_description"]
    template_app_label = None

    def get_object(self, queryset=None):
        try:
            obj = self.model.objects.get(slug="mbc")
        except self.model.DoesNotExist:
            obj = None
        return obj

    def get_ordered_tactics(self):
        if not hasattr(self, "_ordered_tactics"):
            self._ordered_tactics = self.object.tactic_set.order_by(
                "order_weight"
            ).prefetch_related(prefetch_nested_techniques(models.Technique))
        return self._ordered_tactics

    def get_title(self):
        return self.object.name
