from pathlib import Path

from django.apps import AppConfig


HERE = Path(__file__).parent


class MitreMBCConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    label = "mitrembc"
    name = "django_mitre.mbc"
    path = HERE

    def get_matachable_model_patterns(self):
        from . import patterns
        return (
            patterns.SOFTWARE_ID_PATTERN,
            patterns.TACTIC_ID_PATTERN,
            patterns.TECHNIQUE_ID_PATTERN,
        )
