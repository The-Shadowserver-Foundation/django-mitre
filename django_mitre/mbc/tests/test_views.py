from django.test import TestCase
from django.urls import reverse
from model_bakery import baker

from ...core.utils import model_url_name
from ..models import Software


class BaseDetailViewTestCase(TestCase):
    """Testing behavior of base detail view by using SoftwareDetailView"""

    fixtures = [
        "tests/mitreattack/auth_user.json",
    ]

    def setUp(self):
        self.client.login(username="admin", password="password")

    def test_multiple_objects(self):
        id_ = "X0154"
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
