import hashlib

def make_hash(s):
    return hashlib.md5(s.encode()).hexdigest()
