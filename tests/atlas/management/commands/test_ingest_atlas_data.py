import pytest
from django.core.management import call_command

from django_mitre.atlas.management.commands.ingest_atlas_data import Command
from django_mitre.atlas.models import CaseStudy, Collection, Matrix, Mitigation, Tactic, Technique


@pytest.mark.django_db
class TestIngestAtlasData:
    def test_success(self, mocker, atlas_data):
        # We get the data using the github API. This by passes the github interactions
        # and returns the content from our testing data.
        mocker.patch.object(
            Command,
            'index',
            new_callable=mocker.PropertyMock,
            return_value=atlas_data,
        )

        call_command('ingest_atlas_data')

        # The scope of this test is  to ensure the content is ingested.
        # From a high level we can ensure this by looking for specific counts and relationships.

        # Expect a known count for each type.
        assert Collection.objects.count() == 1
        assert Tactic.objects.count() == 16
        assert Technique.objects.count() == 178
        assert Mitigation.objects.count() == 37
        assert CaseStudy.objects.count() == 68
        assert Matrix.objects.count() == 1
        # relationships == 284
