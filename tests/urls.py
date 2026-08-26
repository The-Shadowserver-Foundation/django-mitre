from django.urls import include, path


urlpatterns = [
    path("mitre/", include("django_mitre.core.urls")),
]
