import hashlib

def compute(s):
    return hashlib.sha1(s.encode()).hexdigest()
