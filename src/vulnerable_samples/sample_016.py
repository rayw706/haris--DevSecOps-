import pickle

def load_file(path):
    with open(path,'rb') as f:
        return pickle.load(f)
