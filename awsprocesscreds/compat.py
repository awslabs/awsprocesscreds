import six


if six.PY3:
    from html import escape
else:
    from cgi import escape
