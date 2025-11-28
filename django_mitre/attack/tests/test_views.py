from django.apps import apps
from django.test import TestCase
from django.urls import reverse
from model_bakery import baker

from ...core.utils.model import model_url_name
from ..models import DataSource, Software, Technique
from ..patterns import MATCHABLE_MODEL_PATTERNS


EXAMPLE_IDS = (
    "C0004",
    "DS1010",
    "G2020",
    "M3030",
    "S4040",
    "TA5050",
    "T6060",
)
EXAMPLE_IDS_TO_MODEL_PATTERNS = zip(
    EXAMPLE_IDS,
    MATCHABLE_MODEL_PATTERNS,
    strict=True,
)


class RedirectByIdTestCase(TestCase):
    fixtures = [
        "tests/mitreattack/auth_user.json",
    ]

    def setUp(self):
        # Only need to be authenticated to use this route
        self.client.login(username="nobody", password="password")

    def test_model_redirects(self):
        for id, (
            model_name,
            _expr,
        ) in EXAMPLE_IDS_TO_MODEL_PATTERNS:
            model = apps.get_model(model_name)
            url = reverse("mitreattack:redirect_by_mitre_id", args=[id])
            resp = self.client.get(url)

            expected_redirect_url = reverse(
                model_url_name(model, "detail"),
                args=[id],
            )
            self.assertEqual(resp.url, expected_redirect_url)

    def test_no_matching_id(self):
        for id in (
            "bogus",
            "A7070",
        ):
            url = reverse("mitreattack:redirect_by_mitre_id", args=[id])
            resp = self.client.get(url)
            self.assertEqual(resp.status_code, 400)

    def test_lowercase_id(self):
        examples = [
            # Format: (<id>, <canonical-id>, <model>,)
            # Common case identifier with single letter and extended sub-id
            (
                "t0026.002",
                "T0026.002",
                Technique,
            ),
            # Double char prefixed id
            (
                "ds0001",
                "DS0001",
                DataSource,
            ),
        ]
        for (
            id_,
            canonical_id,
            model,
        ) in examples:
            with self.subTest(id=id_, canonical_id=canonical_id, model=model):
                url = reverse("mitreattack:redirect_by_mitre_id", args=[id_])
                resp = self.client.get(url)
                # Check that we redirect for lowercase identifiers
                self.assertEqual(resp.status_code, 302)
                # Check the redirect location uses the canonical id
                url = reverse(model_url_name(model, "detail"), args=[canonical_id])
                self.assertEqual(resp.headers["location"], url)


class BaseDetailViewTestCase(TestCase):
    """Testing behavior of base detail view by using SoftwareDetailView"""

    fixtures = [
        "tests/mitreattack/auth_user.json",
    ]

    def setUp(self):
        self.client.login(username="admin", password="password")

    def test_multiple_objects(self):
        # The S0154 is an actual case where
        # one object is deprecated and the other object is live.
        id_ = "S0154"
        test_expectation = "FOUND the correct record"

        # Create two objects that share the same ID. The data has a few
        # instances where there are duplicate records for a single Mitre ID.
        # Tests for resolving to the non-deprecated or non-revoked object
        # when there are multiple objects.
        baker.make(Software, mitre_id=id_, name=test_expectation)
        baker.make(Software, mitre_id=id_, deprecated=True)

        url = reverse(model_url_name(Software, "detail"), args=[id_])
        resp = self.client.get(url)
        self.assertEqual(resp.status_code, 200)
        self.assertIn(test_expectation, resp.content.decode("utf8"))
