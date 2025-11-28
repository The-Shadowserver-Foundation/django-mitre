from django.conf import settings


def project_base(request):
    """
    Adds the 'project_base_template' template variable holding the base template name.
    Projects integrating this package can set their base template
    via ``settings.PROJECT_BASE_TEMPLATE``.
    """
    return {
        "project": getattr(settings, "PROJECT_NAME", None),
        "project_base_template": getattr(settings, "PROJECT_BASE_TEMPLATE", None),
    }
