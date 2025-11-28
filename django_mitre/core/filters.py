import django_filtering as filtering


class MitreFilterSet(filtering.FilterSet):
    name = filtering.Filter(
        filtering.InputLookup("istartswith", label="starts with"),
        filtering.InputLookup("icontains", label="contains"),
        filtering.InputLookup("iendswith", label="ends with"),
        default_lookup="icontains",
        label="Name",
    )
    mitre_id = filtering.Filter(
        filtering.InputLookup("icontains", label="contains"),
        default_lookup="icontains",
        label="Mitre ID",
    )
    description = filtering.Filter(
        filtering.InputLookup("icontains", label="contains"),
        default_lookup="icontains",
        label="Description",
    )

    class Meta:
        abstract = True
