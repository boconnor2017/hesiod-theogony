import sys
import subprocess

def install_package(package_name):
    subprocess.check_call(["apt", "-y", "install", "python3-"+package_name])

