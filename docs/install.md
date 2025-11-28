# Installation in a Django project

## Base installation

Add the following to the installed apps setting:

```python
INSTALLED_APPS = [
    # ...
    "django_filtering_ui",
    "django_mitre.core",
    "django_mitre.attack",
    "django_mitre.mbc",
]
```

Add the `project_base` context processor for template integration:

```python
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        # ...
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                # ...
                'django_mitre.core.context_processors.project_base',  # <-- Add this context processor
            ],
        },
    },
]
```

Either enable `TEMPLATES['APP_DIRS'] = True` or have the app directories loader enabled (i.e. `django.template.loaders.app_directories.Loader`).

Optionally include the `GITHUB_ACCESS_TOKEN` in your settings with a GitHub personal access token (PAT).
Without a valid access token the synchronization of the data may fail because of API limitations.
However, requests without the token set should be fine for simple one time ingestions of the data.

There is an assumption that `jquery` is globally available in your base template.
If this is not the case, you'll need to add a jquery script tag to the templates.

Include the URLs to visualize and search the contents. In you project's `urls.py` add:

```python
urlpatterns = [
    # ...
    path("mitre/", include("django_mitre.core.urls")),
]
```

## When using Django <= 4.2

When using Django less than version 5.1, you will need to include the [`django-querystring-tag`](https://pypi.org/project/django-querystring-tag/) package to provide access to the `querystring` template tag, which is otherwise built-in for Django 5.1 and later.

You can include this package through the use of the `django42` package requirement extra like:  `pip install django-mitre[django42]`.

In order to make this package forward and backward compatible, you'll need to add the following setting:

```python
TEMPLATES = [
    {
        # ...
        "OPTIONS": {
            # ...
            # Adds tag to built-ins so that it doesn't need loaded in the template;
            # thus allowing for forward compatibility in django>=5.1.
            "builtins": ["querystring_tag.templatetags.querystring_tag"],
        },
    }
]
```

## Integrating into your project's templates

Set the `PROJECT_BASE_TEMPLATE` setting to your base template.
You may need to provide a shim template to correctly match up template blocks with your project.
See `django_mitre/core/templates/mitrecore/base.html` for the default base template.
