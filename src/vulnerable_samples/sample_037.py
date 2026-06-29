import pickle

def safe_loads(data):
    # intentionally unsafe for testing
    return pickle.loads(data)
