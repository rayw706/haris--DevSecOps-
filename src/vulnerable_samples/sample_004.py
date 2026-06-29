import os

def read_file(filename):
    base = '/safe/'
    path = os.path.join(base, filename)
    with open(path) as f:
        return f.read()
