# Developer notes

The following is an assortment of notes collected over the course of development on this project.

## Note on versions

Versions of the data are essentially updates and additions to entries. We can therefore assume with some certainty that relationships built in one version are retained in the next.

The data contains two identifiers: STIX ID and MITRE ID. These appear to be unchanged between versions. This allows us to consistently sync the data on version changes. However, in practice there is at least one known MITRE ID collision; exceptions have been put in the code to address this.

Removal of data looks to be done through the use of the STIX common property: `revoked`. This means the data continues to live on, though for all intensive purposes it is abandoned by the author. Our usage of this data has been to append "(revoked)" to the name of the item. The `revoked-by` reference relationship should indicate what if anything has replaced it.

### MITRE ATT&CK data import procedure

The [MITRE ATT&CK STIX 2.1 formatted data](https://github.com/mitre-attack/attack-stix-data) is the source of this package's data.
We get updates from this source when MITRE pushes a release. This gives us a stable source of the data MITRE ATT&CK produces.

The data is imported using the `ingest_attack_data` management command (i.e. a django specific command).

    python manage.py ingest_attack_data

To ingest a specific version (latest is default) use `--version-to-ingest <version>`. For example:

    python manage.py ingest_attack_data --version-to-ingest 9.0

The output is verbose by default. To quiet the output use `--quiet`.

    python manage.py ingest_attack_data --quiet

<details>
<summary> Developer notes (click to expand)</summary>

Acquire the data:

    git clone git@github.com:mitre-attack/attack-stix-data.git
    cd attack-stix-data

The data is arranged by three main catagories that are versioned collections (in the STIX sense).

Start by parsing the collections index:

```python
import json
from pathlib import Path

with Path('index.json').open('r') as fb:
    index = json.load(fb)
```

The catagories are:

```python
print(', '.join([c['name'] for c in index['collections']]))
```

To get a list of paths to our local copy of the data use the following line:

```python
collections = [Path(c['versions'][0]['url'].split('/master/')[-1]) for c in index['collections']]
[x.exists() for x in collections]
```

For version 10.1 these are the object counts by type:

- x-mitre-collection: 1
- attack-pattern: 707
- relationship: 14467
- course-of-action: 284
- identity: 1
- intrusion-set: 136
- malware: 475
- tool: 73
- x-mitre-tactic: 14
- x-mitre-matrix: 1
- x-mitre-data-source: 38
- x-mitre-data-component: 109
- marking-definition: 1

This data was obtained using:

```python
ent = json.load(collections[0].open('r'))
by_type = {t:[y for y in ent['objects'] if y['type'] == t] for t in set([x['type'] for x in ent['objects']])}
{k: len(v) for k, v in by_type.items()}
```

</details>


## Modeling

The Mitre terminology doesn't cleanly match with the STIX terminology. This is an attempt to map that terminology and model the items that are different and/or do not exist.

- Intrusion Set :: Groups: STIX 2.1 `intrusion-set`
  - Most likely an exception to the rule, but `G0058` has a duplicate. It's not a problem as long as we address data marked with `x_mitre_deprecated`, which it is.
- Malware :: Software: STIX 2.1 `malware`
- Tool :: Software: STIX 2.1 `tools`
- _ :: Tactics: Custom `x-mitre-tactic`
  - These are children of a Matrix item
  - These are one parent (in a multi parent relationship) to Techniques
  - These are linked to Attack Patterns / Techniques through the Technique's `kill_chain_phases` (array of mappings keyed by `phase_name` in lowercase). `x_mitre_shortname` is a short identifier used specifically for the stix data. `x_mitre_shortname` on the Tactic matches the value of `phase_name` in the Technique.
- Attack Pattern :: Techniques: STIX 2.1 `attack-pattern`
  - Some of these records have a `revoked` property (e.g. `attack-pattern--9b99b83a-1aac-4e29-b975-b374950551a3`). According to the STIX spec, this means this object is "no longer considered valid by the object creator." Interestly, Mitre has redirects for the IDs associated with these. Though our source of data doesn't show how those redirects would be built.
  - Techniques related to other Techniques as sub-techniques.
- _ :: Data Sources: Custom `x-mitre-data-source` & `x-mitre-data-component` (source is parent, component is child)
- Course of Action :: Mitigations: STIX 2.1 `course-of-action`
- Relationship :: References (integrated into other models): STIX 2.1 `relationship`
- _ :: Matrices: Custom `x-mitre-matrix` (visual catagorization of Tactics to relate/contain techniques)
- Identity :: _ :STIX 2.1 `identity` (only one entry for MITRE)
- _ :: Collection: Custom `x-mitre-collection` used to version a set of data

We do little to nothing with the following typed data:
- `x-mitre-collection`: The versioned collection itself. Mostly used in the import process. Also used as a way to know the currently imported version.
- `identity`: This is mostly used to make the STIX data complete. There is only one record for Mitre.
- `x-mitre-matrix`: Basically a container for `x-mitre-tactic`.
- `marking-definition`: unknown.

## Adding a new model

In the instance of a new data-type appearing in the data you'll need to create a new model for it. There are a few steps that will allow the model to be used during ingestion.

1. Create the model for the new data-type
1. Create the identification pattern for the new data-type and link it to the model

   This involves defining a model pattern pair in `django_mitre.<app>.patterns` and placing that defined pair in the `MATCHABLE_MODEL_PATTERNS` of that module.

1. Register the urls for the index and details views

   Include the model pattern pair in the view module's `VIEWABLE_MODELS_AND_PK_PATTERNS`. This will by default generate an index view for the model. You may need to explicitly define an index view to override base behavior. You will also need to define a detail view for the model.

1. Run the tests and correct errors in `utils` and `views` tests
1. Create the ingestion form
1. Create navigation
1. Run the tests and correct errors


## Developer Debug Notes

List the references for generic content-type:

```python
from django.contrib.contenttypes.models import ContentType
from django_mitre.attack.models import *
refs = Reference.objects.filter(source_ref_id=41, source_ref_content_type=ContentType.objects.get_for_model(Malware))
refs.count()
[x for x in refs]
```

---

Print out the Mitre ID that have duplicate records:

```python
from django.db.models import Count
from django_mitre.attack.models import MitreIdentifiableMixIn
from django_mitre.attack.models import ALL_MODELS

for model in ALL_MODELS:
    if not issubclass(model, MitreIdentifiableMixIn):
        continue
    for obj in model.objects.values('mitre_id').annotate(count=Count('mitre_id')
).filter(count__gte=2).all():
        print(model.__name__)
        print(f"- {obj}")
```

---

Find all reference types associated with a model:

```python
from django_mitre.attack.models import *
rel_target_types = set([])
rel_source_types = set([])
model = Malware
for tech in model.objects.filter(revoked=False, deprecated=False).all():
    for ref in tech.target_refs.all():
        rel_target_types.add(ref.relationship_type)
    for ref in tech.source_refs.all():
        rel_source_types.add(ref.relationship_type)
print(f"target and source relationship types: {rel_target_types} and {rel_source_types}")
```

---

List each tactic with the number of techniques and techiques with subtechniques:

```python
from django_mitre.attack.models import *
col = Collection.objects.first()
tactics = Tactic.objects.filter(collection=col).all()
[{tac.name: [tac.techniques.get_active().filter(is_subtechnique=False).count(), {mtec.name: [stec.name for stec in mtec.subtechniques.get_active().all()] for mtec in tac.techniques.get_active().filter(is_subtechnique=False).all()}] for tac in mat.tactic_set.order_by('order_weight').all()} for mat in Matrix.objects.all()]
```
