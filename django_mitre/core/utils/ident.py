from django.apps import apps
from django.db.models import Model

from ...attack.patterns import MATCHABLE_MODEL_PATTERNS as ATTACK_MATCHABLE_MODEL_PATTERNS
from ...mbc.patterns import MATCHABLE_MODEL_PATTERNS as MBC_MATCHABLE_MODEL_PATTERNS


__all__ = (
    "get_model_by_id",
    "get_model_context",
    "get_object_by_id",
)

MATCHABLE_MODEL_PATTERNS_BY_CONTEXT = {
    "mitreattack": ATTACK_MATCHABLE_MODEL_PATTERNS,
    "mitrembc": MBC_MATCHABLE_MODEL_PATTERNS,
    # prioritize attack over mbc when not specified
    None: ATTACK_MATCHABLE_MODEL_PATTERNS + MBC_MATCHABLE_MODEL_PATTERNS,
}


def get_model_context(model_or_object: type[Model] | Model) -> str:
    """Provide the context given a model or instance of a model"""
    for ctx in (
        "mitreattack",
        "mitrembc",
    ):
        for model_name, _ in MATCHABLE_MODEL_PATTERNS_BY_CONTEXT[ctx]:
            model = apps.get_model(model_name)
            if model is model_or_object or isinstance(model_or_object, model):
                return ctx
    raise ValueError("Could not find a context match for the given model or object.")


def get_model_by_id(id_: str, context: str = None) -> type[Model] | None:
    """Retrieve the model given the ``id_`` and ``context`` (i.e. attack or mbc)."""
    try:
        patterns = MATCHABLE_MODEL_PATTERNS_BY_CONTEXT[context]
    except KeyError as exc:
        raise ValueError(f"invalid context specified: {context}") from exc

    for model_name, pattern in patterns:
        match = pattern.match(id_)
        if match:
            return apps.get_model(model_name)
    return None


def get_object_by_id(id_: str, context: str = None) -> Model:
    """Retrieve the object for the given ``id_`` and ``context`` (i.e. attack or mbc).

    Raises ``ValueError`` when the identifier is invalid.
    Raises ``<Model>.DoesNotExist`` when the object cannot be found.

    """
    model = get_model_by_id(id_, context)
    if model is None:
        raise ValueError(f"Invalid identifier: {id_}")

    # Assume we shouldn't allow deprecated or revoked items to be found.
    # Let DoesNotExist raise in the event that the object can't be found.
    return model.objects.get(mitre_id__iexact=id_, deprecated=False, revoked=False)
