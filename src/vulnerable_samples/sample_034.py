import os

def open_file(name):
    with open('/data/' + name) as f:
        return f.read()
