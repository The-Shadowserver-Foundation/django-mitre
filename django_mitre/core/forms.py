from django import forms


class FilterForm(forms.Form):
    q = forms.JSONField(required=False)
