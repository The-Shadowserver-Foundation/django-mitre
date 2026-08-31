from pathlib import Path

from django.apps import AppConfig


HERE = Path(__file__).parent


class MitreAttackConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    label = "mitreatlas"
    name = "django_mitre.atlas"
    path = HERE
