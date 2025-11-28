from django.urls import include, path

from . import views


urlpatterns = [
    path(
        "",
        views.AppIndexView.as_view(title="MITRE"),
        name="mitrecore_index",
    ),
    path("attack/", include("django_mitre.attack.urls")),
    path("mbc/", include("django_mitre.mbc.urls")),
]
