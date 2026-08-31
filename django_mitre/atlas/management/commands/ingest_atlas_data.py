from typing import Any, TypeVar

from django.db.models import Model

from ....core.management.commands._shared import BaseStixIngestionCommand
from ...forms import (
    BaseMitreAtlasModelForm,
    CaseStudyForm,
    MatrixForm,
    MitigationForm,
    TacticForm,
    TechniqueForm,
)
from ...models import (
    CaseStudy,
    Collection,
    Matrix,
    Mitigation,
    Tactic,
    Technique,
)


DATA_TYPES_MAPPING = {
    # Mapping of the key used by the source data to our Model and Form.
    # 'data-key': (<Model>, <ModelForm>)
    # Keys that end with 's' are considered plural; list vs dict.
    'case-studies': (CaseStudy, CaseStudyForm),
    'mitigations': (Mitigation, MitigationForm),
    'tactics': (Tactic, TacticForm),
    'techniques': (Technique, TechniqueForm),
    'matrix': (Matrix, MatrixForm),
}

# Typing variable definition for parameter and return type.
ModelType = TypeVar("ModelType", bound=Model)


class Command(BaseStixIngestionCommand):
    """This ingests the Mitre Atlas data."""

    github_repository_path = "mitre-atlas/atlas-data/"
    index_filepath = "/dist/ATLAS-latest.yaml"
    collection_model = Collection

    # Note, the mitre-atlas/atlas-data repo is structured to contain both the data and
    # a python package. Furthermore, they've got two versioning systems in use
    # that structure CalVer versioned files under the `dist/v6` directory.
    # We can possibly assume all future version will be in this location.
    # If looking for the latest version, we can simply reference `dist/ATLAS-latest.yaml`.

    def ingest(self) -> None:
        # Ingest and synchronize each collection
        collection = self.make_collection()

        # Roll through the content
        for data_type in DATA_TYPES_MAPPING:
            self.log(f" - processing '{data_type}' items...", dim=True)
            model, model_form = DATA_TYPES_MAPPING[data_type]
            plural = data_type.endswith('s')
            data = (
                self.index[data_type]
                if plural
                else {self.index[data_type]['id']: self.index[data_type]}
            )
            objects = self.ingest_objects(data, model, model_form, collection)
            self.log(f"   {len(objects)} {data_type} processed", dim=True)

        # FIXME In Attack and MBC we slugify, cache platforms, and assign sequencing
        #       in a fixup step. Atlas thankfully resolves sequencing through relationships.
        #       It's worth fixing Matrix broadly remove the slug in favor of it becoming
        #       its unofficial id. Atlas takes this approach and it seems sensible enough.
        #       Replacing the hardcoded 'order_weight' assignment with hardcoded relationships
        #       for Attack & MBC could greatly reduce the need for fix ups the Matrix altogether.
        #       Also, Tactics relate to the Matrix through the data's relationships,
        #       which is different from how Attack & MBC relate them.
        # self.fixup_matrices(collection)

        # TODO Fix markdown (e.g. references to internal objects)
        # self.fix_markdown()

    def make_collection(self) -> Collection:
        data = self.index["collection"]
        data.pop('id')
        data.pop('object-type')
        data.pop('references')
        data['created'] = data.pop('created-date')
        data['modified'] = data.pop('modified-date')
        return Collection.objects.create(**data)

    def ingest_objects(
        self,
        data: dict[str, dict[str, Any]],
        model: type[ModelType],
        model_form: type[BaseMitreAtlasModelForm],
        collection: Collection,
    ) -> list[ModelType]:
        """Creates objects from the given ``data``."""
        # TODO Refactor to only use the model_form, which contains reference to the model.
        objects = []
        for mitre_id, item in data.items():
            form_data = item.copy()
            form_data['mitre_original_data'] = item
            form_data['collection'] = collection
            form = model_form(form_data)
            if form.errors:
                # Log the error and continue
                self.log_form_errors(mitre_id, form)
                continue
            obj = form.save()
            self.log_created(obj)
            objects.append(obj)
        return objects
