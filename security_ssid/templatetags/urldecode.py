from urllib.parse import unquote

from django import template

register = template.Library()


@register.filter
def urldecode(value):
    return unquote(value)
