import unittest

from django.apps import apps
from django.test import TestCase
from model_bakery import baker

from django_mitre.attack.patterns import (
    MATCHABLE_MODEL_PATTERNS as ATTACK_MATCHABLE_MODEL_PATTERNS,
)
from django_mitre.mbc.patterns import (
    MATCHABLE_MODEL_PATTERNS as MBC_MATCHABLE_MODEL_PATTERNS,
)

from ...utils import get_model_by_id, get_model_context, get_object_by_id
from ...utils.ident import MATCHABLE_MODEL_PATTERNS_BY_CONTEXT


ATTACK_EXAMPLE_IDS = (
    ["C7070"],
    ["DS1010"],
    ["G2020"],
    ["M3030"],
    ["S4040"],
    ["TA5050"],
    ["T6060", "T1497.001"],
)
MBC_EXAMPLE_IDS = (
    ["X4040", "X0001"],
    ["OC5050", "OB6000"],
    ["C7070", "B1212", "E4040", "E1027.m02", "F1000"],
)
EXAMPLE_IDS = ATTACK_EXAMPLE_IDS + MBC_EXAMPLE_IDS

EXAMPLE_IDS_TO_MODEL_PATTERNS_BY_CONTEXT = {
    "mitreattack": list(zip(ATTACK_EXAMPLE_IDS, ATTACK_MATCHABLE_MODEL_PATTERNS, strict=True)),
    "mitrembc": list(zip(MBC_EXAMPLE_IDS, MBC_MATCHABLE_MODEL_PATTERNS, strict=True)),
}


class GetModelContextTestCase(unittest.TestCase):
    @property
    def target(self):
        return get_model_context

    def test_failure_to_match(self):
        for id in (
            "bogus",
            "A7070",
        ):
            with self.assertRaises(ValueError):
                self.target(id)

    def test_model_detection_success(self):
        for ctx in (
            "mitrembc",
            "mitreattack",
        ):
            for model_name, _ in MATCHABLE_MODEL_PATTERNS_BY_CONTEXT[ctx]:
                model = apps.get_model(model_name)
                with self.subTest(model_name=model_name, model=model):
                    self.assertEqual(self.target(model), ctx)

    def test_object_detection_success(self):
        for ctx in (
            "mitrembc",
            "mitreattack",
        ):
            for model_name, _ in MATCHABLE_MODEL_PATTERNS_BY_CONTEXT[ctx]:
                obj = baker.make(model_name)
                with self.subTest(model_name=model_name, obj=obj):
                    self.assertEqual(self.target(obj), ctx)


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
        for ctx, ids_to_model_pattern in EXAMPLE_IDS_TO_MODEL_PATTERNS_BY_CONTEXT.items():
            for ids, (model_name, _) in ids_to_model_pattern:
                model = apps.get_model(model_name)
                for id in ids:
                    with self.subTest(id=id, ctx=ctx):
                        matched_model = self.target(id, ctx)
                        self.assertEqual(matched_model, model)
                    with self.subTest(id=id.lower(), ctx=ctx):
                        # Check the explicit matching of lowercase identifiers
                        matched_model = self.target(id.lower(), ctx)
                        self.assertEqual(matched_model, model)
                    with self.subTest(id=id, ctx=None):
                        # Check the matching of unspecified context
                        if id.startswith("C"):
                            # C#### ids are in both attack and mbc
                            # Without specifying the context this will fail.
                            pass
                        else:
                            matched_model = self.target(id)
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
        for _, ids_to_model_pattern in EXAMPLE_IDS_TO_MODEL_PATTERNS_BY_CONTEXT.items():
            for ids, (model_name, _) in ids_to_model_pattern:
                model = apps.get_model(model_name)
                for id in ids:
                    context = None
                    if id.startswith("C"):
                        # C#### ids are in both attack and mbc
                        # Without specifying the context this will fail.
                        context = get_model_context(model)

                    with self.subTest(id=id, context=None), self.assertRaises(model.DoesNotExist):
                        self.target(id, context=context)

    def test_success(self):
        for ctx, ids_to_model_pattern in EXAMPLE_IDS_TO_MODEL_PATTERNS_BY_CONTEXT.items():
            for ids, (model, _) in ids_to_model_pattern:
                for id in ids:
                    obj = baker.make(model, mitre_id=id)
                    with self.subTest(id=id, ctx=ctx):
                        found_obj = self.target(id, ctx)
                        self.assertEqual(obj, found_obj)
                    with self.subTest(id=id, ctx=ctx):
                        # Check also for lowercase name matching when requested
                        found_obj = self.target(id.lower(), ctx)
                        self.assertEqual(obj, found_obj)
                    with self.subTest(id=id, ctx=None):
                        # Check the matching of unspecified context
                        if id.startswith("C"):
                            # C#### ids are in both attack and mbc
                            # Without specifying the context this will fail.
                            pass
                        else:
                            found_obj = self.target(id)
                            self.assertEqual(obj, found_obj)
