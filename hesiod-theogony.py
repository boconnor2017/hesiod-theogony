# Description: Primary launch for Theogony
# Author: Brendan O'Connor
# Date: June 2026
# Version: 1.0

# Menu:
#  -help or blank: return menu

# Import Standard Python Libraries
import os
import sys

# Import Hesiod Libraries
from python_lib import logs_and_headers as liblog

# Local Functions
def _main_(args):
    liblog.hesiod_print_header()
    if '--help' in args:
        help_menu()
        sys.exit()

    if '-m1' in args:
        m1()
        sys.exit()
    
    if '-m2' in args:
        m2()
        sys.exit()

    if '-m3' in args:
        m3()
        sys.exit()

    if '-m4' in args:
        m4()
        sys.exit()

    if '-m5' in args:
        m5()
        sys.exit()

    else:
        help_menu()
        sys.exit()

def help_menu():
    print("Menu") 

def m1():
    print("=========================================================")
    print("Launching Theogony: MODULE 1")
    print("=========================================================")

def m2():
    print("=========================================================")
    print("Launching Theogony: MODULE 2")
    print("=========================================================")

def m3():
    print("=========================================================")
    print("Launching Theogony: MODULE 3")
    print("=========================================================")

def m4():
    print("=========================================================")
    print("Launching Theogony: MODULE 4")
    print("=========================================================")

def m5():
    print("=========================================================")
    print("Launching Theogony: MODULE 5")
    print("=========================================================")

# Program Launch
_main_(sys.argv)