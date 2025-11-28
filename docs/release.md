# Notes on the release process

## Building the package

Run the following:

    pip install hatchling twine
    hatchling build

See also [Packaging your package](https://packaging.python.org/en/latest/guides/distributing-packages-using-setuptools/#packaging-your-project)

This produces a tarball (source build) and wheel that can be found
in the `dist` directory.

## Releasing the package

It gets released as a wheel (`.whl` extension) and tarball:

    twine upload dist/*

To tag the project use:

    git tag -a v$(hatchling metadata version)
