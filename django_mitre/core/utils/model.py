import collections.abc

from django.apps import apps
from django.db.models import AutoField, Field, Model


def model_fields(
    model: Model,
    include: list[str] | None = None,
    exclude: list[str] | None = None,
) -> list[Field]:
    """
    Return a list of model fields,
    except those that are auto created or not editable
    (e.g: id, created_by, created_at, updated_by, updated_at)

    However, if a non-editable field is explicitly included in
    "include", then it will be returned.
    """
    fields = []
    for f in model._meta.fields:
        is_auto = f.auto_created or isinstance(f, AutoField)
        if not is_auto and (f.editable or (include and f.name in include)):
            fields.append(f)

    if include:
        fields = [f for f in fields if f.name in include]
        if isinstance(include, collections.abc.Sequence):
            include = list(include)
            # Then the fields we were given are in some order. Go by
            # that ordering, not by the order they appear on the
            # model.
            fields = sorted(fields, key=lambda field: include.index(field.name))
    if exclude:
        fields = [f for f in fields if f.name not in exclude]
    return fields


def model_url_name(
    model_or_instance: str | Model | type[Model],
    action: str,
    namespaced: bool = True,
    **kwargs,
) -> str:
    """
    Return a URL name using a naming convention (e.g. '<app_label>:<model_label>_<action>').
    """
    if isinstance(model_or_instance, str):
        model = apps.get_model(model_or_instance)
    else:
        model = model_or_instance._meta.model
    model_name = model._meta.model_name
    name = f"{model_name}_{action}"
    if namespaced:
        app = model._meta.app_label
        name = f"{app}:{name}"
    return name
