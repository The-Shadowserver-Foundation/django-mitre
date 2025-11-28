import json
from base64 import b64decode

import github
from django.conf import settings
from django.core.management.base import BaseCommand
from django.db import transaction
from django.urls import reverse
from django.utils.functional import cached_property
from django.utils.text import slugify


try:
    import ipdb as pdb
except ImportError:
    import pdb


ONE_MEGABYTE = 1024 * 1024

MITRE_CONTENT_TYPES = (
    # Collection gets associated with all other content-types
    "x-mitre-collection",
    "marking-definition",
    "course-of-action",
    "identity",
    "intrusion-set",
    "malware",
    "tool",
    "x-mitre-data-source",
    "x-mitre-data-component",
    "x-mitre-tactic",
    "attack-pattern",
    "campaign",
    # Matrix is parent to Tactic, where the data to build the relationship
    # is only found in the `x-mitre-matix` record.
    "x-mitre-matrix",
    # Relationship associates all content-types, which is why it must be last.
    "relationship",
)

# Matrices have tactics that should be displayed in an exscallation of
# information or leverage order. This information is not present
# in the STIX data. The following is the order as appears in the mitre site.
MITRE_TACTICS_ORDER_WEIGHTS_BY_NAME = {
    "Reconnaissance": 10,
    "Resource Development": 20,
    "Initial Access": 30,
    "Anti-Behavioral Analysis": 34,
    "Anti-Static Analysis": 36,
    "Execution": 40,
    "Persistence": 50,
    "Privilege Escalation": 60,
    "Defense Evasion": 70,
    "Evasion": 80,
    "Credential Access": 90,
    "Discovery": 100,
    "Lateral Movement": 110,
    "Collection": 120,
    "Command and Control": 130,
    "Exfiltration": 140,
    "Inhibit Response Function": 150,
    "Impair Process Control": 160,
    "Impact": 170,
    "Network Effects": 180,
    "Remote Service Effects": 190,
    "Communication Micro-objective": 200,
    "Cryptography Micro-objective": 210,
    "Data Micro-objective": 220,
    "File System Micro-objective": 230,
    "Hardware Micro-objective": 240,
    "Memory Micro-objective": 250,
    "Operating System Micro-objective": 260,
    "Process Micro-objective": 270,
}


class IngestionLoggingMixIn:
    def _write(self, stream, message, **kwargs):
        # Assumes options have been set to self.
        if self.options["verbosity"] < 0:
            # Silence all output
            return
        stream.write(message, **kwargs)
        stream.flush()

    def out(self, message, **kwargs):
        """Write to standard out"""
        self._write(self.stdout, message, **kwargs)

    def err(self, message, **kwargs):
        """Write to standard error"""
        self._write(self.stderr, message, **kwargs)

    def log(self, message, **kwargs):
        """Log a message to standard out"""
        if kwargs.pop("dim", None):
            # Wrap text in ANSI dim and reset escapes (i.e. grey it out).
            kwargs["style_func"] = lambda s: f"\x1b[2m{s}\x1b[m"
        self.out(message, **kwargs)

    def log_created(self, message, **kwargs):
        """Log the creation of something"""
        if self.options["verbosity"] <= 2:
            return
        kwargs["style_func"] = lambda s: f"\x1b[32m{s}\x1b[0m"
        self.log("\u2714 created {message}", **kwargs)

    def log_updated(self, message, **kwargs):
        """Log an update of something"""
        if self.options["verbosity"] <= 2:
            return
        # Wrap text in ANSI dim and reset escapes (i.e. grey it out).
        kwargs["style_func"] = lambda s: f"\x1b[33m{s}\x1b[0m"
        self.log("\u2714 updated {message}", **kwargs)

    def log_error(self, message, **kwargs):
        """Log an update of something"""
        # Wrap text in ANSI dim and reset escapes (i.e. grey it out).
        kwargs["style_func"] = lambda s: f"\x1b[31m{s}\x1b[0m"
        self.log("\u2718 error {message}", **kwargs)

    def log_warning(self, message, **kwargs):
        """Log a warning"""
        # Wrap text in ANSI dim and reset escapes (i.e. grey it out).
        kwargs["style_func"] = lambda s: f"\x1b[34m{s}\x1b[0m"
        self.log("\u2706 warning {message}", **kwargs)

    def log_form_errors(self, id, form):
        """Log the errors of the given form"""
        field_msgs = "\n".join(
            [f"  - {f} has errors: {', '.join(errs)}" for f, errs in form.errors.items()]
        )
        msg = f"'{id}' - these fields had errors while parsing {form!r}:\n{field_msgs}"
        self.log_error(msg)


class BaseStixIngestionCommand(BaseCommand, IngestionLoggingMixIn):
    """Command to ingests mitre STIX 2.1 data."""

    #: repo path in github.com/org/repo, where the org/repo is the repo path
    github_repository_path = None
    #: filepath to the json file within the repository that contains the index file
    index_filepath = None

    # Abstract attributes that need to be assigned by the inheriting class
    model_cls_by_data_type = None
    collection_model = None

    @property
    def github_access_token(self) -> str | None:
        """Retrieve the PAT (Personal Access Token) from settings.
        Use ``None`` for any falsy value, because the github library will
        attempt to use anything but ``None``.

        The GitHub API requests for public content are honored
        without an access token but you'll be rate-limited to 60
        requests per hour. The limit increases to 5,000
        requests per hour if you set up an access token first:
        - https://developer.github.com/v3/#rate-limiting
        - https://github.com/settings/tokens

        """
        if getattr(settings, "GITHUB_ACCESS_TOKEN", None):
            return settings.GITHUB_ACCESS_TOKEN
        return None

    def add_arguments(self, parser):
        super().add_arguments(parser)
        parser.add_argument(
            "--quiet",
            action="store_true",
            help="run without any output",
        )
        parser.add_argument(
            "--pdb",
            action="store_true",
            help="Drop into pdb on error.",
        )

    def handle(self, *args, **options) -> None:
        try:
            self.options = options
            self.options["verbosity"] = -1 if self.options["quiet"] else self.options["verbosity"]
            self.atomic_ingest()
        except Exception:
            if self.options["pdb"]:
                pdb.post_mortem()
            else:
                raise

    @transaction.atomic
    def atomic_ingest(self) -> None:
        self.flush()
        self.ingest()

    def flush(self) -> None:
        """Flush all the previously ingested data"""
        # All the data is connected to a Collection object.
        # Deletion of the collection will cascade delete all the data.
        self.log("Removing all previous Collections")
        for col in self.collection_model.objects.all():
            self.log(f" - deleting '{col}'...", dim=True)
            col.delete()

    def ingest(self) -> None:
        """Main abstract command to be called when handling the command."""
        raise NotImplementedError("This is an abstract method")

    def get_github_access_token(self):
        return self.github_access_token

    @cached_property
    def github(self):
        return github.Github(self.get_github_access_token())

    def get_repository_path(self):
        return self.github_repository_path

    @cached_property
    def repo(self):
        return self.github.get_repo(self.get_repository_path())

    def get_target_git_sha(self, version=None):
        """Returns the git sha for the commit targetted.
        If ``version`` is supplied that will be used to find
        the git sha for the tagged version.

        """
        return github.GithubObject.NotSet

    def get_index_filepath(self):
        return self.index_filepath

    @cached_property
    def index(self):
        return self._fetch_json_content(self.get_index_filepath())

    def get_index_contents_by_type(self, index):
        """Returns the index keyed by content-type"""
        return {
            t: [y for y in index["objects"] if y["type"] == t]
            # iterate to obtain all available types
            for t in {x["type"] for x in index["objects"]}
        }

    def get_object_by_stix_identifier(self, stix_identifier):
        data_type = stix_identifier.split("--", 1)[0]
        model = self.model_cls_by_data_type[data_type][0]
        obj = model.objects.get(mitre_stix_identifier=stix_identifier)
        return obj

    def fixup_matrices(self, collection) -> None:
        qs = collection.matrix_set.all()
        needs_sub_slug = False
        if qs.count() > 1:
            needs_sub_slug = True
        for matrix in collection.matrix_set.all():
            self.slugify_matrix(matrix, needs_sub_slug)
            self.cache_matrix_platforms(matrix)
            self.provide_order_weighting_to_tactics(matrix)

    def slugify_matrix(self, matrix, needs_sub_slug=False) -> None:
        """the URL slugs for Matrix records"""
        self.log(f"Assigning Matrix slug for '{matrix}'.")
        slug = slugify(matrix.collection.name.split()[0].lower())
        if needs_sub_slug:
            slug += f"/{slugify(matrix.name)}"
        matrix.slug = slug
        matrix.save()

        url = reverse("mitreattack:matrix_detail_by_collection", kwargs={"slug": slug})
        # Log the URLs incase there are new matrices available.
        # These are hardcoded into the site navigation.
        self.log(f"- matrix '{matrix}' available at: {url}", dim=True)

    def cache_matrix_platforms(self, matrix) -> None:
        """Cache the list of known platforms for use in filter techniques
        by platform on the the matrix page.
        Without this cached valued we'd be required to query techniques
        by matrix tactics and then produce a set of platforms.

        """
        self.log(f"Caching technique platforms Matrix '{matrix}'.")
        platforms = set()
        for tactic in matrix.tactic_set.get_active().all():
            for technique in tactic.techniques.get_active().all():
                if technique.platforms is None:
                    continue
                for plat in technique.platforms:
                    platforms.add(plat)
        matrix.platforms = sorted(platforms)
        matrix.save()
        if matrix.platforms:
            self.log(
                f" - set Matrix '{matrix}' platforms: {', '.join(matrix.platforms)}",
                dim=True,
            )

    def provide_order_weighting_to_tactics(self, matrix) -> None:
        """Associates a order weight to the Tactics
        so that they display in a specific order.

        """
        self.log("Applying order weights to tactics.")
        for t in matrix.tactic_set.all():
            try:
                order_weight = MITRE_TACTICS_ORDER_WEIGHTS_BY_NAME[t.name]
            except KeyError:
                self.log_error(f"{t} could not be given a order weight (name: {t.name})")
                continue
            t.order_weight = order_weight
            self.log_updated(f"{t} order weight set to {order_weight}.")
            t.save()

    def _fetch_content(self, filepath):
        target_ref = self.get_target_git_sha()
        # The github api won't fetch large files
        # But you need a github.ContentFile's info in order
        # to have enough information to ask for the file as a blob.
        # To work around this we list the parent directory
        # to obtain the github.ContentFile instance for the specific file.
        parent_dir, filename = filepath.rsplit("/", 1)
        parent_dir = parent_dir if parent_dir else "/"
        try:
            content_file = [
                x
                for x in self.repo.get_contents(parent_dir, ref=target_ref)
                if x.name == filename
            ][0]
        except IndexError as exc:
            self.log_error(f"couldn't find {filepath} in the repository")
            raise Exception("requested file could not be found") from exc

        if content_file.size > ONE_MEGABYTE:
            self.log(f"Fetching {filepath} ({content_file.size} bytes)", dim=True)
            content_blob = self.repo.get_git_blob(content_file.sha)
            if content_blob.encoding != "base64":
                raise Exception("Unrecognised encoding: {content_blob.encoding}")
            content_bytes = b64decode(content_blob.content)
        else:
            content_bytes = content_file.decoded_content
        return content_bytes.decode("utf8")

    def _fetch_json_content(self, filepath):
        content = self._fetch_content(filepath)
        self.log(f"Parsing {filepath} as JSON data", dim=True)
        return json.loads(content)

    def _check_for_new_content_types(self, types) -> set[str]:
        known_types = set(MITRE_CONTENT_TYPES)
        given_types = set(types)
        new_types = set()

        # Test whether every element in given_types is in known_types.
        if not (known_types >= given_types):
            # There is an unknown type in the given_types.
            # Produce a new set with elements
            # in either the known_types or given_types but not both,
            # then reduce the resulting set with elements in the set that are not in known_types.
            new_types = (known_types ^ given_types) - known_types
            self.log_warning(
                "discovered new content-type(s) in mitre data: "
                f"'{', '.join(new_types)}'; please look into this"
            )
        return new_types
