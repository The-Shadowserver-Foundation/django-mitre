from django import forms

from .models import (
    CaseStudy,
    Matrix,
    Mitigation,
    Tactic,
    Technique,
)


class BaseMitreAtlasModelForm(forms.ModelForm):
    """Base Mitre model form"""

    MITRE_ID_PREFIX = 'AML.'

    class Meta:
        abstract = True

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Replace dash with underscore in dictionary key names.
        self.data = {k.replace('-', '_'): v for k, v in self.data.items()}

        # Determine identifying information
        assert 'mitre_original_data' in self.data
        self.data['mitre_id'] = self._get_mitre_id(with_prefix=False)
        self.data['mitre_id_complete'] = self._get_mitre_id()

        self.data['created'] = self.data.pop('created_date')
        self.data['modified'] = self.data.pop('modified_date')

    def _get_mitre_id(self, with_prefix: bool = True):
        id = self.data['mitre_original_data']['id']
        return (
            id[len(self.MITRE_ID_PREFIX) :]
            if (not with_prefix and self.MITRE_ID_PREFIX in id)
            else id
        )


# ########################################################################## #


class CaseStudyForm(BaseMitreAtlasModelForm):
    class Meta:
        model = CaseStudy
        fields = '__all__'


class MatrixForm(BaseMitreAtlasModelForm):
    class Meta:
        model = Matrix
        fields = '__all__'


class MitigationForm(BaseMitreAtlasModelForm):
    class Meta:
        model = Mitigation
        fields = '__all__'


class TacticForm(BaseMitreAtlasModelForm):
    class Meta:
        model = Tactic
        fields = '__all__'


class TechniqueForm(BaseMitreAtlasModelForm):
    class Meta:
        model = Technique
        fields = '__all__'
        exclude = (
            'is_subtechnique',
            'major_technique',
        )
