import subprocess

def run_safe(args):
    subprocess.run(args, shell=False)
