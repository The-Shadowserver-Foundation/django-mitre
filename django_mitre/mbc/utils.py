from functools import partial

from ..core.utils.ident import get_model_by_id as core_get_model_by_id
from ..core.utils.ident import get_object_by_id as core_get_object_by_id
from . import patterns


__all__ = (
    "get_model_by_id",
    "get_object_by_id",
)

get_model_by_id = partial(core_get_model_by_id, context=patterns.app_label)
get_object_by_id = partial(core_get_object_by_id, context=patterns.app_label)
