#!/usr/bin/env bash
set -Eeo pipefail

# A flag file used to indicate that the application has been initialized
INITIALIZED_FLAG_FILE="/.initialized"
DJANGO_SUPERUSER_NAME="${DJANGO_SUPERUSER_NAME:-admin}"
DJANGO_SUPERUSER_PASSWORD="${DJANGO_SUPERUSER_PASSWORD:-password}"

APP_SRC_ROOT="/app/src"
DEV_PKG_ROOT="/app/dev"

_install_dev_packages() {
    echo "* Looking for developer packages..."
    # Installs the development packages
    if [[ -n "$DEV_PKGS" ]]; then
        # Array of packages to be installed
        pkg_paths=()
        # Array of packages to be installed from PyPI
        pypi_pkgs=()
        # Split the DEV_PKGS variable by ' ' and iterate through each package
        IFS==' ' read -r -a packages <<< "$DEV_PKGS"
        for pkg in "${packages[@]}"; do
            path="${DEV_PKG_ROOT}/${pkg}"
            if [ -e "${path}" ]; then
                echo "  * Preparing to install '${pkg}' for development..."
                pkg_paths+=("$path")
            else
                echo "  * Failed to find '${path}' for installing '${pkg}'. Deferring to PyPI for install..."
                pypi_pkgs+=("${pkg}")
            fi
        done
        if [ ${#pkg_paths[@]} -gt 0 ]; then
            echo "  * Installing development packages"
            python -m pip install $(printf -- " -e %s" "${pkg_paths[@]}")
        fi
        if [ ${#pypi_pkgs[@]} -gt 0 ]; then
            echo "  * Installing released development packages"
            python -m pip install $(printf -- "%s " "${pypi_pkgs[@]}")
        fi

    else
        echo "  * No development packages to install."
    fi
}

_main() {
    if [ ! -e "$INITIALIZED_FLAG_FILE" ]; then
        # Be careful what you put in this section. The flag file is not placed
        # in a volume, which means it does not persist between container runs
        # (e.g. `docker compose run --rm <name> <cmd>`)

        _install_dev_packages

        echo "* Running migrations..."
        python manage.py migrate
        echo "* Create project superuser..."
        # Creates a superuser named root
        # Note, the password is in DJANGO_SUPERUSER_PASSWORD and looked up by the createsuperuser command.
        python manage.py createsuperuser --no-input --username $DJANGO_SUPERUSER_NAME --email=admin@example.faux || echo "'$DJANGO_SUPERUSER_NAME' superuser already exists"

        # Stop initialization on subsequent runs
        touch $INITIALIZED_FLAG_FILE
    fi

    exec "$@"
}


_main "$@"
