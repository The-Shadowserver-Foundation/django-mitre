# Example

This package's repository contains an example Django project integrating the `django-mitre` package.

## Using the Example Project

The `example` directory located in this repository contains an example Django project with the apps loaded within it.
This small project provides an example usage of the django-mitre packages within a Django project.

Use the following to start the project:

    cd example/
    docker compose up -d


The project is then viewable at http://localhost:8000/.

At a later time, you can stop using application using: `docker compose down`.

The project is not preloaded with data.
You will need to run the ingestion commands to load the data:

```sh
docker compose exec project ./manage.py ingest_attack_data
docker compose exec project ./manage.py ingest_mbc_data
```

These commands load the project with the latest version of the MITRE ATT&CK and Malware Behavior Catalog (MBC) data.

Please [report any issues](https://github.com/The-Shadowserver-Foundation/django-mitre/issues/new) you come across.
Please note that the upstream MITRE ATT&CK data changes regularly.
It's usual for ingestion of the latest version of the data to fail.
The ingestion typically needs adjusted every few months as the MITRE team changes the [ATT&CK Data Model](https://mitre-attack.github.io/attack-data-model/schemas/) (contributions and insights welcome).

If you run into an error running `ingest_attack_data`, you can try specifying the previous
version of the data using the `--version-to-ingest <version>` option.

Feel free to provide feedback or suggestions. Thank you for trying the project.
