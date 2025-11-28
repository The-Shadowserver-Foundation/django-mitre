from datetime import datetime

from django.core.exceptions import ObjectDoesNotExist
from django.urls import reverse
from django.utils.functional import cached_property
from django.utils.text import slugify

from ....core.management.commands._shared import (
    MITRE_CONTENT_TYPES,
    BaseStixIngestionCommand,
)
from ...forms import MODEL_CLS_BY_DATA_TYPE
from ...models import Collection, Matrix, Technique


class Command(BaseStixIngestionCommand):
    github_repository_path = "MBCProject/mbc-stix2"
    index_filepath = "/mbc/mbc.json"
    model_cls_by_data_type = MODEL_CLS_BY_DATA_TYPE
    collection_model = Collection

    def ingest(self):
        # Ingest and synchronize each the contents of the bundle
        self._desired_version = self.latest_version
        collection = self.sync_collection(self.index)
        self.fixup_matrices(collection)

    @cached_property
    def latest_version(self):
        tag = self.repo.get_tags()[0]
        return tag.name.lstrip("v")

    def get_target_git_sha(self, version=None):
        """Returns the git sha for the commit targetted.
        If ``version`` is supplied that will be used to find
        the git sha for the tagged version.

        """
        if version is None:
            version = self.latest_version
        tag_name = f"v{version}"
        try:
            tag = [t for t in self.repo.get_tags() if t.name == tag_name][0]
        except IndexError as exc:
            raise ValueError(f"invalid version requested: {version}") from exc
        return tag.commit.sha

    def create_collection(self, version) -> Collection:
        """Create a Collection object for the version"""
        # The MBC data does not have a Collection object, so we hardcode some information.

        # Look up the singular collection object in the index.
        collection_data = {
            # Hardcoded because MBC data does not have a collection
            "mitre_stix_identifier": "x-mitre-collection--7a452523-f141-4be7-9ab4-4ba6f42fc991",
            "name": "MBC (Malware Behavior Catalog)",
            "description": (
                "The Malware Behavior Catalog (MBC) is a catalog of malware "
                "objectives and behaviors, created to support malware "
                "analysis-oriented use cases, such as labeling, similarity "
                "analysis, and standardized reporting."
            ),
            "applied": datetime.now(),
            "version": version,
            "shortname": "mbc",
        }

        self.log(
            f"Ingesting {collection_data['name']} version {collection_data['version']} contents:"
        )
        try:
            collection_instance = self.get_object_by_stix_identifier(
                collection_data["mitre_stix_identifier"]
            )
        except ObjectDoesNotExist:
            collection_instance = None
        collection_model, collection_form_model = MODEL_CLS_BY_DATA_TYPE["x-mitre-collection"]
        form = collection_form_model(collection_data, instance=collection_instance)
        collection = form.save()
        return collection

    def sync_collection(self, index) -> Collection:  # noqa: C901
        contents_by_type = self.get_index_contents_by_type(index)
        # Check for new unknown types
        self._check_for_new_content_types(contents_by_type.keys())

        # Create or obtain the encapsulating Collection.
        collection = self.create_collection(self._desired_version)

        # Sort the contents by type
        items = sorted(contents_by_type.items(), key=lambda x: MITRE_CONTENT_TYPES.index(x[0]))
        # Roll through the content
        for data_type, values in items:
            if data_type in ("x-mitre-collection",):
                # Do not process these within this loop
                continue
            self.log(f" - processing stix '{data_type}' items...", dim=True)
            try:
                model, model_form = MODEL_CLS_BY_DATA_TYPE[data_type]
            except KeyError:
                # No matching model
                continue
            processed_count = 0
            for data in values:
                form_data = data.copy()
                id = data.get("id")
                try:
                    instance = model.objects.get(mitre_stix_identifier=id)
                except model.DoesNotExist:
                    instance = None
                form_data["mitre_original_data"] = data
                form_data["mitre_stix_identifier"] = id
                form_data["collection"] = collection
                form_data["deprecated"] = data.get("x_mitre_deprecated", False)
                form = model_form(form_data, instance=instance)
                if form.errors:
                    # Log the error and continue
                    self.log_form_errors(id, form)
                    continue
                obj = form.save()
                if instance is None:
                    self.log_created(obj)
                elif form.has_changed() and instance is not None:
                    self.log_updated(obj)
                processed_count += 1
            self.log(f"   {processed_count} processed", dim=True)

        self.log(" - relating major techniques to subtechniques...", dim=True)
        # Now circle back through Techniques to associate sub-Techniques
        # Some sub-techniques are created before their major technique.
        for tech in Technique.objects.filter(is_subtechnique=True, major_technique=None).all():
            # Sub-techniques have a mitre ID like T0000.000,
            # where the ID is in two parts: <major>.<sub>
            major_id = tech.mitre_id.split(".")[0]
            try:
                major_tech = Technique.objects.get(mitre_id=major_id)
                tech.major_technique = major_tech
                tech.save()
            except Technique.DoesNotExist:
                self.log_error(
                    f"the major technique for sub-technique '{tech.mitre_id}' cannot be found"
                )
            else:
                self.log_created(
                    f"relationship between major technique '{major_tech}' "
                    f"and subtechnique '{tech}'"
                )
        return collection

    def slugify_matrix(self, matrix: Matrix, needs_sub_slug=False) -> None:
        self.log(f"Assigning Matrix slug for '{matrix}'.")
        slug = slugify(matrix.collection.name.split()[0].lower())
        matrix.slug = slug
        matrix.save()

        url = reverse("mitrembc:matrix_index")
        # Log the URLs incase there are new matrices available.
        # These are hardcoded into the site navigation.
        self.log(f"- matrix '{matrix}' available at: {url}", dim=True)
