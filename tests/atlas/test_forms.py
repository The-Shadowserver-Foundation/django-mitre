import pytest
from model_bakery import baker

from django_mitre.atlas.forms import (
    CaseStudyForm,
    MatrixForm,
    MitigationForm,
    TacticForm,
    TechniqueForm,
)
from django_mitre.atlas.models import CaseStudy, Collection, Matrix, Mitigation, Tactic, Technique


@pytest.mark.django_db
class FormTestCase:
    pass


class TestCaseStudyForm(FormTestCase):
    def test_success(self, atlas_data):
        collection = baker.make(Collection)

        data = atlas_data['case-studies']['AML.CS0000']
        form_data = data.copy()
        form_data['mitre_original_data'] = data
        form_data['collection'] = collection

        form = CaseStudyForm(form_data)
        assert not form.errors

        obj = form.save()
        assert isinstance(obj, CaseStudy)

        assert str(obj.uuid) == data['uuid']
        assert obj.mitre_id == data['id'][4:]
        assert obj.mitre_id_complete == data['id']
        assert obj.created.isoformat() == data['created-date']
        assert obj.modified.isoformat() == data['modified-date']

        assert obj.name == data['name']
        assert obj.description == data['description']

        assert obj.type == data['type']
        assert obj.actor == data['actor']
        assert obj.target == data['target']
        assert obj.reporter is None
        assert obj.date.isoformat() == data['date']
        assert obj.date_granularity == data['date-granularity']


class TestMatrixForm(FormTestCase):
    def test_success(self, atlas_data):
        collection = baker.make(Collection)

        data = atlas_data['matrix']
        form_data = data.copy()
        form_data['mitre_original_data'] = data
        form_data['collection'] = collection

        form = MatrixForm(form_data)
        assert not form.errors

        obj = form.save()
        assert isinstance(obj, Matrix)

        assert str(obj.uuid) == data['uuid']
        assert obj.mitre_id == data['id']
        assert obj.mitre_id_complete == data['id']
        assert obj.created.isoformat() == data['created-date']
        assert obj.modified.isoformat() == data['modified-date']

        assert obj.name == data['name']
        assert obj.description == data['description']


class TestMitigationForm(FormTestCase):
    def test_success(self, atlas_data):
        collection = baker.make(Collection)

        data = atlas_data['mitigations']['AML.M0000']
        form_data = data.copy()
        form_data['mitre_original_data'] = data
        form_data['collection'] = collection

        form = MitigationForm(form_data)
        assert not form.errors

        obj = form.save()
        assert isinstance(obj, Mitigation)

        assert str(obj.uuid) == data['uuid']
        assert obj.mitre_id == data['id'][4:]
        assert obj.mitre_id_complete == data['id']
        assert obj.created.isoformat() == data['created-date']
        assert obj.modified.isoformat() == data['modified-date']

        assert obj.name == data['name']
        assert obj.description == data['description']

        assert obj.lifecycle_phases == data['lifecycle-phases']
        assert obj.categories == data['categories']


class TestTacticForm(FormTestCase):
    def test_success(self, atlas_data):
        collection = baker.make(Collection)

        data = atlas_data['tactics']['AML.TA0000']
        form_data = data.copy()
        form_data['mitre_original_data'] = data
        form_data['collection'] = collection

        form = TacticForm(form_data)
        assert not form.errors

        obj = form.save()
        assert isinstance(obj, Tactic)

        assert str(obj.uuid) == data['uuid']
        assert obj.mitre_id == data['id'][4:]
        assert obj.mitre_id_complete == data['id']
        assert obj.created.isoformat() == data['created-date']
        assert obj.modified.isoformat() == data['modified-date']

        assert obj.name == data['name']
        assert obj.description == data['description']


class TestTechniqueForm(FormTestCase):
    def test_success(self, atlas_data):
        collection = baker.make(Collection)

        data = atlas_data['techniques']['AML.T0000']
        form_data = data.copy()
        form_data['mitre_original_data'] = data
        form_data['collection'] = collection

        form = TechniqueForm(form_data)
        assert not form.errors

        obj = form.save()
        assert isinstance(obj, Technique)

        assert str(obj.uuid) == data['uuid']
        assert obj.mitre_id == data['id'][4:]
        assert obj.mitre_id_complete == data['id']
        assert obj.created.isoformat() == data['created-date']
        assert obj.modified.isoformat() == data['modified-date']

        assert obj.name == data['name']
        assert obj.description == data['description']

        assert obj.platforms == data['platforms']
        assert obj.maturity == data['maturity']
        assert obj.attack_reference == data['attack-reference']
