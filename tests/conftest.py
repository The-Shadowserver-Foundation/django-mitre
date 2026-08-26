import django


def pytest_configure(config):
    from django.conf import settings

    templates_options_builtins = (
        # Adds the `querystring` template tag to built-ins,
        # so that it does not need loaded to be used in templates;
        # thus allowing for forward compatibility in django>=5.1.
        "querystring_tag.templatetags.querystring_tag" if django.VERSION < (5,) else None,
    )

    settings.configure(
        DATABASES={
            'default': {'ENGINE': 'django.db.backends.sqlite3', 'NAME': ':memory:'},
        },
        DEBUG=True,
        DEBUG_PROPAGATE_EXCEPTIONS=True,
        INSTALLED_APPS=[
            "django.contrib.auth",
            "django.contrib.contenttypes",
            "django.contrib.sessions",
            "django.contrib.messages",
            "django_filtering",
            "django_filtering_ui",
            "django_mitre.core",
            "django_mitre.attack",
            "django_mitre.mbc",
        ],
        ROOT_URLCONF='tests.urls',
        SECRET_KEY='seekret',
        TEMPLATES=[
            {
                'BACKEND': 'django.template.backends.django.DjangoTemplates',
                'DIRS': [],
                'APP_DIRS': True,
                'OPTIONS': {
                    'context_processors': [
                        'django.template.context_processors.debug',
                        'django.template.context_processors.request',
                        'django.contrib.auth.context_processors.auth',
                        'django.contrib.messages.context_processors.messages',
                        'django_mitre.core.context_processors.project_base',
                    ],
                    "builtins": [x for x in templates_options_builtins if x],
                },
            },
        ],
    )

    django.setup()
