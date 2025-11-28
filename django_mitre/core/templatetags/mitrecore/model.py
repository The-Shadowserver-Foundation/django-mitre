from django.template import Library


register = Library()

@register.simple_tag(takes_context=True)
def field_value(context, field_name, **kwargs):
    return getattr(context['object'], field_name)
