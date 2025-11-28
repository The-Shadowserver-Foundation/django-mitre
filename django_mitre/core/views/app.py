from typing import Any

from django.apps import apps
from django.shortcuts import reverse
from django.urls.exceptions import NoReverseMatch
from django.views.generic import TemplateView

from ..utils import model_url_name


__all__ = ("AppIndexView",)


class AppIndexView(TemplateView):
    template_name = "mitrecore/app-index.html"
    #: Title to for the page
    title: str = ""
    #: Name of the app for this index
    app_name: str = ""

    @property
    def links(self) -> list[dict[str, Any]]:
        if not self.app_name:
            return []
        app = apps.get_app_config(self.app_name)
        items = []
        for model in app.get_models():
            try:
                items.append({
                    "title": model._meta.verbose_name_plural.title(),
                    "url": reverse(model_url_name(model, "index")),
                })
            except NoReverseMatch:
                continue
        return items

    @property
    def extra_context(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "links": self.links,
        }
