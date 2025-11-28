import re

from django.core.exceptions import ObjectDoesNotExist
from django.db.models import Model

from ....core.management.commands._shared import (
    MITRE_CONTENT_TYPES,
    BaseStixIngestionCommand,
)
from ...forms import MODEL_CLS_BY_DATA_TYPE
from ...models import (
    Collection,
    DataSource,
    DescriptiveMixIn,
    Group,
    Mitigation,
    Software,
    Tactic,
    Technique,
)
from ...templatetags.mitreattack_tags import model_url


MITRE_ATTACK_GITHUB_REPO_PATH = "mitre-attack/attack-stix-data"


class Command(BaseStixIngestionCommand):
    """This ingests and syncs the mitre attack data from STIX 2.1 data source."""

    github_repository_path = MITRE_ATTACK_GITHUB_REPO_PATH
    index_filepath = "/index.json"
    model_cls_by_data_type = MODEL_CLS_BY_DATA_TYPE
    collection_model = Collection

    def add_arguments(self, parser):
        super().add_arguments(parser)
        parser.add_argument(
            "--version-to-ingest",
            action="store",
            help="The data version to ingest (defaults to latest version)",
        )

    def ingest(self) -> None:
        version = self.options["version_to_ingest"]
        # Ingest and synchronize each collection
        for collection_index in self.get_collections(version):
            collection = self.sync_collection(collection_index)
            self.fixup_matrices(collection)

        # Fix markdown (e.g. references to internal objects)
        self.fix_markdown()

    def get_collections(self, version=None):
        """Uses the mitre attack data repository's index
        to find the requested ``version``.
        If the requested version isn't available
        an error message will show,
        but the process will continue.

        The ``version`` may be ``None``
        to designate using the latest version of the collections.

        Returns a list of parsed collections.

        """
        collections = []
        for collection in self.index["collections"]:
            if version is None:
                # versions are in decending ordered
                version_info = collection["versions"][0]
            else:
                try:
                    # Roll through the versions to find the target version
                    version_info = [x for x in collection["versions"] if x["version"] == version][
                        0
                    ]
                except IndexError:
                    self.log_error(
                        f"couldn't find version {version} for {collection['name']} collection"
                    )
                    continue
            # URL is something like:
            # https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-10.1.json
            # Therefore, the relative path appears after the term '/master'.
            relative_path = version_info["url"].split("/master")[-1]
            # Lookup and parse the collection
            collections.append(self._fetch_json_content(relative_path))
        return collections

    def get_index_contents_by_type(self, index):
        """returns the index keyed by content-type"""
        return {
            t: [y for y in index["objects"] if y["type"] == t]
            # iterate to obtain all available types
            for t in {x["type"] for x in index["objects"]}
        }

    def sync_collection(self, index) -> Collection:  # noqa: C901
        contents_by_type = self.get_index_contents_by_type(index)

        # Look up the singular collection object in the index.
        collection_data = contents_by_type["x-mitre-collection"][0]
        self.log(
            f"Syncing {collection_data['name']} "
            f"version {collection_data['x_mitre_version']} contents:"
        )
        collection_data["version"] = collection_data["x_mitre_version"]
        collection_id = collection_data["mitre_stix_identifier"] = collection_data["id"]
        collection_data["shortname"] = collection_data["name"].replace(" ATT&CK", "").lower()
        try:
            collection_instance = self.get_object_by_stix_identifier(collection_id)
        except ObjectDoesNotExist:
            collection_instance = None
        collection_model, collection_form_model = MODEL_CLS_BY_DATA_TYPE["x-mitre-collection"]
        form = collection_form_model(collection_data, instance=collection_instance)
        collection = form.save()

        # Check for new unknown types
        new_content_types = self._check_for_new_content_types(contents_by_type.keys())

        # Filter out any new types
        items = [
            (
                data_type,
                values,
            )
            for data_type, values in contents_by_type.items()
            if data_type not in new_content_types
        ]
        # Sort the contents by type
        items = sorted(items, key=lambda x: MITRE_CONTENT_TYPES.index(x[0]))
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

    def fix_markdown(self):
        """Roll over each descriptive model to fix the markdown"""
        self.log("Fixing markdown...")
        for model in (x[0] for x in MODEL_CLS_BY_DATA_TYPE.values()):
            if not issubclass(model, DescriptiveMixIn):
                # Model has no descriptive properties
                continue
            self.log(f"Fixing markdown for model: {model}", dim=True)
            # Ignore revoked and deprecated records
            for obj in model.objects.all():
                has_changed = False
                for field in (
                    "description",
                    "detection_description",
                ):
                    has_changed = rewrite_markdown(obj, field) or has_changed
                if has_changed:
                    obj.save()
                    self.log_updated(f"markdown for {obj}")


def rewrite_markdown(obj, field: str) -> bool:
    """Rewrite the markdown of the given object at the given field."""
    changed = False
    if not hasattr(obj, field):
        return changed
    value = getattr(obj, field, "")
    result = rewrite_markdown_urls(value)
    result = rewrite_citations(result, obj)
    if value != result:
        changed = True
        setattr(obj, field, result)
    return changed


def rewrite_markdown_urls(value: str):
    """Match on markdown links and change the url"""
    value_pos = 0
    new_value = ""
    for match in link_matcher(value):
        new_value += value[value_pos : match.start]
        url = translate_url(value[match])
        new_value += url
        value_pos = match.stop
    new_value += value[value_pos:]
    return new_value


link_part = re.compile(r"\]\((?P<link>https://attack\.mitre\.org/[\w/.]+)\)", re.MULTILINE)


def link_matcher(v: str) -> slice:
    """Match links that go to https://attack.mitre.org
    Returns a ``slice`` for the found link.

    """
    pos = 0
    while True:
        m = link_part.search(v, pos)
        if m:
            yield slice(
                m.start() + 2,
                m.end() - 1,
            )
            pos = m.end()
        else:
            return


# e.g. https://attack.mitre.org/groups/G0007
URL_PARTS = re.compile(r"^https://attack.mitre.org/(?P<type>[\w]+)/(?P<identifier>[\w/]+)$")


def translate_url(url: str) -> str:
    """
    Translates a URL from a mitre.org URLs to local URLs.
    """
    m = URL_PARTS.search(url)
    mitre_type = m.group("type")
    mitre_id = m.group("identifier")
    mitre_id = mitre_id.rstrip("/").replace("/", ".")  # e.g. T1218/011/
    model = mitre_type_to_model(mitre_type)

    if model is None:
        # For mitre types we are not familiar with, use the original url
        # and tack on an anchor that may lead the developer back to this code.
        # We need to be able to ignore unknown types to prevent updates,
        # but we also don't want to amputate the data.
        return url + "#unknown-mitre-type"

    try:
        # We should be able to use .get() here instead of .first().
        # However, there is one or two records that have duplicate ids.
        # To circumvent this issue we order the records and get the first one.
        obj = (
            model.objects.filter(mitre_id=mitre_id)
            # Order the results by non-revoked and non-deprecated first
            .order_by("revoked", "deprecated")
            .first()
        )
    except model.DoesNotExist:
        # If this happens... We should raise and inspect the data.
        # At the very least we should be good citizens are report the problem
        # upstream.
        print(f"Could not find record for {url}. Likely a bug in the data.")
        print(
            "Please analyze this problem and report data integrity issues "
            "to the upstream project: "
            f"github.com/{MITRE_ATTACK_GITHUB_REPO_PATH}"
        )
        raise

    if obj.revoked:
        try:
            # Follow the revoked-by reference to find the active object
            obj = (
                obj.source_refs
                # Looking for the relationship that revoked the record
                .filter(relationship_type="revoked-by")
                # Order by the most recently created record
                .order_by("-created", "-modified")
                .first()
                .target_ref
            )
        except obj.DoesNotExist:
            # Print some info about the problem, but don't do
            # anything about it. User will be shown a
            # deprecation/revocation warning in the description.
            print(
                f"Could not find recent record for the revoked '{mitre_id}'. "
                "Likely a bug in the data."
            )

    return model_url(obj, "detail")


def rewrite_citations(value: str, obj):
    """Rewrite the citations of the given ``value``
    using the objects (given as ``obj``) references
    to create markdown links.

    """
    value_pos = 0
    new_value = ""
    for match_slice, match_text in citation_matcher(value):
        new_value += value[value_pos : match_slice.start]
        new_citation_text = translate_citation(match_text, obj)
        new_value += f"(Citation: {new_citation_text})"
        value_pos = match_slice.stop
    new_value += value[value_pos:]
    return new_value


citation_regex = re.compile(r"\(Citation: (?P<text>[\w\s\-_]+)\)", re.MULTILINE)


def citation_matcher(v: str) -> slice:
    """Match citations of the form ``(Citation: <text>)``
    Returns a ``slice`` for the found citation's outer parathesis
    and inner ``text``.

    """
    pos = 0
    while True:
        m = citation_regex.search(v, pos)
        if m:
            yield slice(m.start(), m.end()), m.group("text")
            pos = m.end()
        else:
            return


def translate_citation(text: str, obj) -> str:
    """Translates citation text to a markdown link"""
    # Find the citiation reference
    info = None
    for ref in obj.mitre_original_data.get("external_references", []):
        if ref["source_name"] == text:
            info = ref
            break
    if info is None:
        # Fall back to the original citation text
        return text
    if "url" not in info:
        result = '[{source_name}]( "{description}")'.format(**info)
    else:
        # Return markdown formatted link: [text](url "title")
        result = '[{source_name}]({url} "{description}")'.format(**info)
    return result


def mitre_type_to_model(mitre_type: str) -> Model | None:
    """Maps a mitre url named type to a model"""
    try:
        return {
            "tactics": Tactic,
            "techniques": Technique,
            "datasources": DataSource,
            "mitigations": Mitigation,
            "groups": Group,
            "software": Software,
        }[mitre_type]
    except KeyError:
        return None
