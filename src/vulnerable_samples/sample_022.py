import hashlib

def good_hash(s):
    return hashlib.sha256(s.encode()).hexdigest()
