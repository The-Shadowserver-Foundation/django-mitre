from django.db.models import Prefetch


def prefetch_nested_techniques(technique_model):
    # Note: When using `Prefetch` on a queryset with filtering applied
    # it's recommended to also use the `to_attr` argument, which assigns
    # the prefetched result to a custom attribute and therefore avoids
    # any potential confusion with the default relation manager.

    # However, using the `to_attr` argument also triggers different
    # behaviour where the result appears as a list and not a queryset.

    # https://docs.djangoproject.com/en/4.2/ref/models/querysets/#prefetch-related

    qs_active_techniques = technique_model.objects.get_active()
    qs_active_major_techniques = technique_model.objects.get_active().filter(
        is_subtechnique=False
    )

    prefetch_subtechniques = Prefetch(
        "subtechniques",
        queryset=qs_active_techniques,
        to_attr="active_subtechniques",
    )

    prefetch_techniques = Prefetch(
        "techniques",
        queryset=qs_active_major_techniques.prefetch_related(prefetch_subtechniques),
        to_attr="active_major_techniques",
    )

    return prefetch_techniques
