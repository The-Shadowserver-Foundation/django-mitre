import unittest

from django.apps import apps
from django.db.models import Model
from django.test import TestCase
from model_bakery import baker

from ..patterns import MATCHABLE_MODEL_PATTERNS
from ..utils import get_model_by_id, get_object_by_id


EXAMPLE_IDS = (
    ["C0004"],
    ["DS1010"],
    ["G2020"],
    ["M3030"],
    ["S4040"],
    ["TA5050"],
    ["T6060", "T1497.001"],
)
EXAMPLE_IDS_TO_MODEL_PATTERNS = list(
    zip(
        EXAMPLE_IDS,
        MATCHABLE_MODEL_PATTERNS,
        strict=True,
    )
)


class GetModelByIdTestCase(unittest.TestCase):
    @property
    def target(self):
        return get_model_by_id

    def test_failure_to_match(self):
        for id in (
            "bogus",
            "A7070",
        ):
            model = self.target(id)
            self.assertIsNone(model)

    def test_success(self):
        for ids, (
            model_name,
            _expr,
        ) in EXAMPLE_IDS_TO_MODEL_PATTERNS:
            model = apps.get_model(model_name)
            for id in ids:
                matched_model = self.target(id)
                self.assertTrue(issubclass(matched_model, Model), "not a Model")
                self.assertEqual(matched_model, model)
                # Check also the explicit matching of lowercase identifiers
                matched_model = self.target(id.lower())
                self.assertEqual(matched_model, model)


class GetObjectByIdTestCase(TestCase):
    @property
    def target(self):
        return get_object_by_id

    def test_failure_to_match(self):
        for id in (
            "bogus",
            "A7070",
        ):
            with self.assertRaises(ValueError):
                self.target(id)

    def test_failure_to_find(self):
        # Testing for non-existent object, but a valid identifier
        for ids, (
            model_name,
            _expr,
        ) in EXAMPLE_IDS_TO_MODEL_PATTERNS:
            model = apps.get_model(model_name)
            for id in ids:
                with self.assertRaises(model.DoesNotExist):
                    self.target(id)

    def test_success(self):
        for ids, (
            model_name,
            _expr,
        ) in EXAMPLE_IDS_TO_MODEL_PATTERNS:
            model = apps.get_model(model_name)
            for id in ids:
                obj = baker.make(model, mitre_id=id)
                found_obj = self.target(id)
                self.assertEqual(obj, found_obj)
                # Check also for lowercase name matching when requested
                found_obj = self.target(id.lower())
                self.assertEqual(obj, found_obj)
