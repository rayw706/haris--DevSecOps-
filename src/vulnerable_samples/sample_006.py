from flask import render_template_string

def greet(name):
    return render_template_string("<h1>Hello %s</h1>" % name)
