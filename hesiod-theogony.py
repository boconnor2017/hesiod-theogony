# Description: Primary launch for Theogony
# Author: Brendan O'Connor
# Date: June 2026
# Version: 1.0

# Menu:
#  -help or blank: return menu

# Import Standard Python Libraries
import os
import sys

# Local Functions
def _main_(args):
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
    print("m1")

def m2():
    print("m2")

def m3():
    print("m3")

def m4():
    print("m4")

def m5():
    print("m5")

# Program Launch
_main_(sys.argv)