import markdown as md
from django.template import Library
from django.template.defaultfilters import stringfilter


register = Library()

@register.filter()
@stringfilter
def markdown(value, options=None):
    """Transfor the Markdown (as ``value``) to HTML."""
    extensions = ["markdown.extensions.fenced_code"]
    return md.markdown(value, extensions=extensions)
