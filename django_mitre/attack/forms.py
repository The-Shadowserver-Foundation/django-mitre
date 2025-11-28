"""\
This app does not have web based forms,
but the forms are used for the creation of objects
in the synchronization command
(i.e. ``python manage.py sync_mitreattack_data``).

The synchronization logic maps the STIX data type to the Model and form.
This mapping is defined here as: ``MODEL_CLS_BY_DATA_TYPE``.
By default, if a form doesn't exist for a model, it is created on import.
However, if the developer (you) wishes to create a custom form class,
be sure to register the form class in the mapping
using the ``register_model_form`` decorator.

"""

from contextlib import suppress

from django import forms
from django.db import models

from .models import (
    ALL_MODELS,
    Campaign,
    DataComponent,
    DataSource,
    Matrix,
    MitreIdentifiableMixIn,
    Reference,
    Software,
    Tactic,
    Technique,
)


MODEL_CLS_BY_DATA_TYPE = {}
# ... see further down in this module for the population of the MODEL_CLS_BY_DATA_TYPE mapping


def _get_form_base_class_by_model(model):
    """Obtain the base class to use for the form by inspecting the model

    For example::

        @register_model_form(Strategy)
        class StrategyForm(_get_form_base_class_by_model(Strategy)):
            ...

    """
    form_cls_inheritance = [BaseMitreModelForm]
    if issubclass(model, MitreIdentifiableMixIn):
        form_cls_inheritance.append(BaseMitreIdentifiableFormMixIn)
    if len(form_cls_inheritance) == 1:
        base_form = form_cls_inheritance[0]
    else:
        base_form = type(f"Base{model.__name__}Form", tuple(form_cls_inheritance), {})
    return base_form


def register_model_form(model):
    """Decorator to register a ModelForm to a model

    For example::

        @register_model_form(Strategy)
        class StrategyForm(_get_form_base_class_by_model(Strategy)):
            ...

    This would result in the ``Strategy`` model being registered
    with this form in the ``MODEL_CLS_BY_DATA_TYPE`` mapping.

    """

    def _reg(form_cls):
        for data_type in model.stix_data_types:
            MODEL_CLS_BY_DATA_TYPE[data_type] = (
                model,
                form_cls,
            )

    def decor(form_cls):
        _reg(form_cls)
        # pass-through, this does not modify the decorated class
        return form_cls

    return decor


class StixIdentifierField(forms.Field):
    """Takes a STIX Identifier of the form ``<content-type>--<uuid>``
    and finds the related object.

    """

    def to_python(self, value):
        if isinstance(value, models.Model):
            return value
        data_type = value.split("--", 1)[0]
        try:
            model = MODEL_CLS_BY_DATA_TYPE[data_type][0]
        except KeyError as exc:
            raise forms.ValidationError(
                f"Unknown data-type '{data_type}' cannot be processed",
                code="invalid",
            ) from exc
        try:
            obj = model.objects.get(mitre_stix_identifier=value)
        except model.DoesNotExist:
            raise forms.ValidationError(
                f"Object for {value} not found",
                code="invalid",
            ) from None
        return obj


class MultipleStixIdentifierField(forms.Field):
    """Takes a list of STIX Identifiers of the form ``<content-type>--<uuid>``
    and finds the related object.

    """

    def to_python(self, value):
        objs = []
        for v in value:
            if isinstance(v, models.Model):
                objs.append(v)
                continue
            data_type = v.split("--", 1)[0]
            model = MODEL_CLS_BY_DATA_TYPE[data_type][0]
            try:
                obj = model.objects.get(mitre_stix_identifier=v)
            except model.DoesNotExist:
                raise forms.ValidationError(
                    f"Object for {v} not found",
                    code="invalid",
                ) from None
            objs.append(obj)
        return objs


class BaseMitreModelForm(forms.ModelForm):
    """Base Mitre model form"""

    class Meta:
        abstract = True

    # Date cleaning methods to work around the following error:
    #   ValueError: MySQL backend does not support timezone-aware datetimes when USE_TZ is False.
    def clean_created(self):
        return self.cleaned_data["created"].replace(tzinfo=None)

    def clean_modified(self):
        return self.cleaned_data["modified"].replace(tzinfo=None)


class BaseMitreIdentifiableFormMixIn(forms.ModelForm):
    """Form mix-in for Mitre Identifiable content-types
    (those that inherit from MitreIdentifiableMixIn).

    This form derives the mitre identifiable field values
    from the initial data.

    """

    class Meta:
        abstract = True

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        try:
            mitre_ref = [
                ref
                for ref in self.data["mitre_original_data"].get("external_references", [])
                if ref.get("source_name")
                in (
                    "mitre-attack",
                    "mitre-mobile-attack",
                    "mitre-ics-attack",
                    "mitre-mbc",
                )
            ][0]
        except IndexError:
            msg = "data is missing 'external_references' for 'mitre-attack'"
            self.add_error("mitre_id", msg)
            self.add_error("mitre_url", msg)
        else:
            # Standard external reference fields
            # See https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_72bcfr3t79jx
            self.data["mitre_id"] = mitre_ref["external_id"]
            self.data["mitre_url"] = mitre_ref["url"]


# Dynamically create the model form classes for each model
# Register the model and form classes for lookup by STIX data-type
for model in ALL_MODELS:
    base_form = _get_form_base_class_by_model(model)
    form_cls = forms.modelform_factory(model, form=base_form, fields="__all__")
    for data_type in model.stix_data_types:
        MODEL_CLS_BY_DATA_TYPE[data_type] = (
            model,
            form_cls,
        )


# Allow for importing of the created ModelForm classes
_locals = locals()
for _model, form in MODEL_CLS_BY_DATA_TYPE.values():
    _locals[form.__name__] = form


# ########################################################################## #
#   Definition of Custom Logic Forms
# ########################################################################## #
# Define forms that have additional logic below this point.


@register_model_form(Reference)
class ReferenceForm(_get_form_base_class_by_model(Reference)):
    source_ref = StixIdentifierField(required=True)
    target_ref = StixIdentifierField(required=True)

    class Meta:
        model = Reference
        fields = "__all__"

    def _save_m2m(self):
        # Form fields don't map to attributes.
        # GenericForeignKey creates two fields on the model:
        # <name>_id & <name>_content_type
        # ModelForm creates/updates suggests this method
        # for many-to-many relationships. This isn't the case,
        # but it is a complex relationship none the less.

        # Save the GenericForeignKey fields
        self.instance.source_ref = self.cleaned_data["source_ref"]
        self.instance.target_ref = self.cleaned_data["target_ref"]
        super()._save_m2m()

    def save(self, *args, **kwargs):
        should_commit = kwargs.get("commit", True)
        # Change commit so relationships can be made
        kwargs["commit"] = False

        obj = super().save(*args, **kwargs)
        # save(commit=False) create the `save_m2m` method
        self.save_m2m()

        # Respect the caller's original intent
        if should_commit:
            obj.save()

        return obj


@register_model_form(Matrix)
class MatrixForm(_get_form_base_class_by_model(Matrix)):
    # The Matrix has the only reference to Tactics
    tactic_refs = MultipleStixIdentifierField(required=True)

    class Meta:
        model = Matrix
        fields = "__all__"
        exclude = ("slug",)

    def _save_m2m(self):
        # Must save the instance in order to associate the Tactics
        self.instance.save()
        # Save the Tactics relationship
        for tactic in self.cleaned_data["tactic_refs"]:
            self.instance.tactic_set.add(tactic)
        super()._save_m2m()

    def save(self, *args, **kwargs):
        should_commit = kwargs.get("commit", True)
        # Change commit so relationships can be made
        kwargs["commit"] = False

        obj = super().save(*args, **kwargs)
        # save(commit=False) create the `save_m2m` method
        self.save_m2m()

        # Respect the caller's original intent
        if should_commit:
            obj.save()

        return obj


@register_model_form(Technique)
class TechniqueForm(_get_form_base_class_by_model(Technique)):
    # Techniques reference Tactics through ``kill_chain_phases``
    # example value: [
    #   {'phase_name': 'credential-access', 'kill_chain_name': 'mitre-attack'},
    #   {'phase_name': 'collection', 'kill_chain_name': 'mitre-attack'},
    # ]
    kill_chain_phases = forms.JSONField(required=False)
    x_mitre_is_subtechnique = forms.BooleanField(required=False, initial=False)
    x_mitre_detection = forms.CharField(required=False)
    x_mitre_platforms = forms.JSONField(required=False)
    x_mitre_version = forms.CharField(required=False)
    x_mitre_contributors = forms.JSONField(required=False)
    x_mitre_permissions_required = forms.JSONField(required=False)
    x_mitre_data_sources = forms.JSONField(required=False)
    x_mitre_system_requirements = forms.JSONField(required=False)

    class Meta:
        model = Technique
        fields = "__all__"
        exclude = (
            "is_subtechnique",
            "major_technique",
            "detection_description",
            "platforms",
            "version",
            "contributors",
            "permissions_required",
            "data_sources",
            "system_requirements",
        )

    def _save_m2m(self):
        # Must save the instance in order to associate the Tactics
        self.instance.save()

        kill_chain_phases = (
            []
            if self.cleaned_data["kill_chain_phases"] is None
            else self.cleaned_data["kill_chain_phases"]
        )
        # Save the Tactics relationship
        for chain in kill_chain_phases:
            tactic = Tactic.objects.filter(
                shortname=chain["phase_name"],
                collection=self.instance.collection,
            ).get()
            self.instance.tactic_set.add(tactic)
        super()._save_m2m()

    def save(self, *args, **kwargs):
        should_commit = kwargs.get("commit", True)
        # Change commit so relationships can be made
        kwargs["commit"] = False

        obj = super().save(*args, **kwargs)
        obj.detection_description = self.cleaned_data["x_mitre_detection"]
        obj.platforms = self.cleaned_data["x_mitre_platforms"]
        obj.version = self.cleaned_data["x_mitre_version"]
        obj.contributors = self.cleaned_data["x_mitre_contributors"]
        obj.permissions_required = self.cleaned_data["x_mitre_permissions_required"]
        obj.system_requirements = (
            self.cleaned_data["x_mitre_system_requirements"][0]
            if self.cleaned_data.get("x_mitre_system_requirements")
            else None
        )
        obj.data_sources = self.cleaned_data["x_mitre_data_sources"]

        # Save specific re-mapped fields
        obj.is_subtechnique = self.cleaned_data["x_mitre_is_subtechnique"]
        if obj.is_subtechnique:
            major_technique_id = self.cleaned_data["mitre_id"].split(".")[0]
            # May not exist yet, but we won't fret over it.
            with suppress(Technique.DoesNotExist):
                obj.major_technique = Technique.objects.get(mitre_id=major_technique_id)

        # save(commit=False) create the `save_m2m` method
        self.save_m2m()

        # Respect the caller's original intent
        if should_commit:
            obj.save()

        return obj


@register_model_form(Tactic)
class TacticForm(_get_form_base_class_by_model(Tactic)):
    x_mitre_shortname = forms.CharField()

    class Meta:
        model = Tactic
        fields = "__all__"
        exclude = ("shortname",)

    def save(self, *args, **kwargs):
        should_commit = kwargs.get("commit", True)
        # Change commit so relationships can be made
        kwargs["commit"] = False

        obj = super().save(*args, **kwargs)
        obj.shortname = self.cleaned_data["x_mitre_shortname"]

        # Respect the caller's original intent
        if should_commit:
            obj.save()

        return obj


@register_model_form(DataSource)
class DataSourceForm(_get_form_base_class_by_model(DataSource)):
    x_mitre_platforms = forms.JSONField(required=False)
    x_mitre_version = forms.CharField(required=False)
    x_mitre_contributors = forms.JSONField(required=False)

    class Meta:
        model = DataSource
        fields = "__all__"
        exclude = (
            "platforms",
            "version",
            "contributors",
        )

    def save(self, *args, **kwargs):
        should_commit = kwargs.get("commit", True)
        # Change commit so relationships can be made
        kwargs["commit"] = False

        obj = super().save(*args, **kwargs)
        obj.platforms = self.cleaned_data["x_mitre_platforms"]
        obj.version = self.cleaned_data["x_mitre_version"]
        obj.contributors = self.cleaned_data["x_mitre_contributors"]

        # Respect the caller's original intent
        if should_commit:
            obj.save()

        return obj


@register_model_form(DataComponent)
class DataComponentForm(_get_form_base_class_by_model(DataComponent)):
    x_mitre_data_source_ref = StixIdentifierField(required=True)

    class Meta:
        model = DataComponent
        fields = "__all__"
        exclude = ("data_source_ref",)

    def _save_m2m(self):
        # Save the ForeignKey field
        self.instance.data_source_ref = self.cleaned_data["x_mitre_data_source_ref"]
        super()._save_m2m()

    def save(self, *args, **kwargs):
        should_commit = kwargs.get("commit", True)
        # Change commit so relationships can be made
        kwargs["commit"] = False

        obj = super().save(*args, **kwargs)
        # save(commit=False) create the `save_m2m` method
        self.save_m2m()

        # Respect the caller's original intent
        if should_commit:
            obj.save()

        return obj


@register_model_form(Software)
class SoftwareForm(_get_form_base_class_by_model(Software)):
    x_mitre_aliases = forms.JSONField(required=False)
    x_mitre_platforms = forms.JSONField(required=False)
    x_mitre_version = forms.CharField(required=False)
    x_mitre_contributors = forms.JSONField(required=False)

    class Meta:
        model = Software
        fields = "__all__"
        exclude = (
            "aliases",
            "platforms",
            "version",
            "contributors",
        )

    def save(self, *args, **kwargs):
        should_commit = kwargs.get("commit", True)
        # Change commit so relationships can be made
        kwargs["commit"] = False

        obj = super().save(*args, **kwargs)
        obj.aliases = self.cleaned_data["x_mitre_aliases"]
        obj.platforms = self.cleaned_data["x_mitre_platforms"]
        obj.version = self.cleaned_data["x_mitre_version"]
        obj.contributors = self.cleaned_data["x_mitre_contributors"]

        # Respect the caller's original intent
        if should_commit:
            obj.save()

        return obj


@register_model_form(Campaign)
class CampaignForm(_get_form_base_class_by_model(Campaign)):
    x_mitre_version = forms.CharField(required=False)
    x_mitre_first_seen_citation = forms.CharField(required=False)
    x_mitre_last_seen_citation = forms.CharField(required=False)

    class Meta:
        model = Campaign
        fields = "__all__"
        exclude = (
            "version",
            "first_seen_citation",
            "last_seen_citation",
        )

    # Date cleaning methods to work around the following error:
    #   ValueError: MySQL backend does not support timezone-aware datetimes when USE_TZ is False
    def clean_first_seen(self):
        return self.cleaned_data["first_seen"].replace(tzinfo=None)

    def clean_last_seen(self):
        return self.cleaned_data["last_seen"].replace(tzinfo=None)

    def save(self, *args, **kwargs):
        should_commit = kwargs.get("commit", True)
        # Change commit so relationships can be made
        kwargs["commit"] = False

        obj = super().save(*args, **kwargs)
        obj.version = self.cleaned_data["x_mitre_version"]
        obj.first_seen_citation = self.cleaned_data["x_mitre_first_seen_citation"]
        obj.last_seen_citation = self.cleaned_data["x_mitre_last_seen_citation"]

        # Respect the caller's original intent
        if should_commit:
            obj.save()

        return obj
