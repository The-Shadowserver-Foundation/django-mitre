from django import template
from django.template.defaultfilters import stringfilter
from django.urls import reverse

from ...core.utils import model_fields, model_url_name


register = template.Library()


@register.inclusion_tag("mitreattack/display_mitre_references_by_type.html", takes_context=True)
def display_mitre_target_references_by_type(context, relationship_type, title=None):
    """Display a listing of target References by a specific type
    (i.e. ``Reference.relationship_type``).
    A target reference is one where the Reference object
    has the contextual object set as ``Reference.target_ref``.

    ``title`` can be supplied as a human readable section title.

    """
    qs = context["object"].target_refs.filter(relationship_type=relationship_type)
    references = [x.source_ref for x in qs if not x.source_ref.deprecated]

    if not references:
        return {"references": []}

    return {
        "title": title,
        "references": references,
    }


@register.inclusion_tag(
    "mitreattack/display_mitre_target_detects_references.html", takes_context=True
)
def display_mitre_target_detects_references(context, title=None):
    """Display a listing of target References by the 'detects'
    relationship (i.e. ``Reference.relationship_type``).
    A target reference is one where the Reference object
    has the contextual object set as ``Reference.target_ref``.

    ``title`` can be supplied as a human readable section title.

    This template tag exists separate from
    ``display_mitre_references_by_type`` because the DataComponent
    model is not an independently viewable type. So it doen't easily
    fit the mold.

    """
    return display_mitre_target_references_by_type(context, "detects", title=title)


@register.inclusion_tag("mitreattack/display_mitre_references_by_type.html", takes_context=True)
def display_mitre_source_references_by_type(context, relationship_type, title=None):
    """Display a listing of source References by a specific type
    (i.e. ``Reference.relationship_type``).
    A source reference is one where the Reference object
    has the contextual object set as ``Reference.source_ref``.

    ``title`` can be supplied as a human readable section title.

    """
    qs = context["object"].source_refs.filter(relationship_type=relationship_type)
    references = [x.target_ref for x in qs if not x.target_ref.deprecated]

    if not references:
        return {"references": []}

    return {
        "title": title,
        "references": references,
    }


@register.inclusion_tag(
    "mitreattack/display_mitre_data_component_references.html", takes_context=True
)
def display_mitre_data_component_references(context):
    data_components = context["object"].datacomponent_set.get_active()
    return {
        # view is needed by templatetag in the template.
        "view": context["view"],
        "data_source": context["object"],
        "title": "Data Components",
        "data_components": data_components,
    }


@register.inclusion_tag("mitreattack/display_mitre_tactic_techniques.html", takes_context=True)
def display_mitre_tactic_techniques(context, fields="name,description"):
    qs = context["object"].techniques.get_active()
    techniques = {}
    if qs.count() == 0:
        return {"techniques": {}}

    model = qs.first()._meta.model
    fields = model_fields(model, include=fields.split(","))

    for tech in qs:
        if tech.is_subtechnique:
            techniques.setdefault(tech.major_technique, [])
            techniques[tech.major_technique].append(tech)
        else:
            techniques.setdefault(tech, [])

    return {
        "view": context["view"],
        "fields": fields,
        "techniques": techniques,
        "title": "Techniques",
    }


@register.filter()
@stringfilter
def first_sentence(value):
    """Return the first sentence"""
    if not value:
        return value
    # This assumes the line breaks at paragraph end.
    output = value.splitlines()[0].split(". ")[0]
    if not output.endswith("."):
        output += "."
    return output


@register.simple_tag()
def model_url(model_or_instance, view="index"):
    """Given a model (or instance of a model) produce the url
    for that model. If an ``view`` name (default ``index``) is given,
    use that view name in the assembly of the url.

    """
    url_name = model_url_name(model_or_instance, view)

    # Not an exhaustive list of possible pk required url view names.
    pk_required_urls = (
        "detail",
        "create",
        "update",
        "delete",
        "review",
    )

    import inspect

    instance = None if inspect.isclass(model_or_instance) else model_or_instance

    if instance and view in pk_required_urls:
        if hasattr(instance, "mitre_id"):
            # If the instance has a mitre_id,
            # it is assumed the view object lookup is through the slug field.
            url = reverse(url_name, kwargs={"slug": instance.mitre_id})
        else:
            url = reverse(url_name, kwargs={"pk": instance.id})
    else:
        url = reverse(url_name)

    return url


@register.inclusion_tag("mitreattack/list_techniques_for_tactic.html", takes_context=True)
def list_techniques_for_tactic(context, tactic):
    return {
        "project": context.get("project"),
        "techniques": tactic.active_major_techniques,
    }
