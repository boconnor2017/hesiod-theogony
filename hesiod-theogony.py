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
    user_options = ['n', 'n', 'n']
    if '--help' in args:
        help_menu()
        sys.exit()

    else:
        help_menu()
        sys.exit()

def help_menu():
    print("Menu") 

# Program Launch
_main_(sys.argv)