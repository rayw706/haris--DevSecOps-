from flask import Markup

def unsafe(html):
    return Markup(html)
