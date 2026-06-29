import subprocess

def list_files(user):
    subprocess.run(['ls', user])
