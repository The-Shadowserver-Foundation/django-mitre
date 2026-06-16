# MITRE ATT&CK and MBC for Django

This package utilizes MITRE's open data to incorporate their knowledge base into a Django project. The indented goal of this project is to provide the data as Django Models for integration into project's that reference MITRE. The display of that information is secondary and only available because it is advantageous to be able to visualize the data in a familiar way.

This project syncs with the open data provided by MITRE in various git repositories in STIX 2.1 format. We consume that data into database records and slightly modify the data for better visual representation.


## Installation in a Django project

Please refer to the [installation docs](docs/install.md) for details.


### Using the Example Project

There is an `example` directory located in this repository that contains an example Django project with the apps loaded within it. See [usage docs](docs/example.md) for details.


## Contributing

Please see the [contributing docs](docs/contribute.md) for details.


## License

GPL v3 (see `LICENSE` file)


## Copyright

© 2026 The Shadowserver Foundation
