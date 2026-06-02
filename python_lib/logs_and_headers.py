# Hesiod Custom Headers and Logs Python Library 2024
# Author: Brendan O'Connor
# Date: January 2024
# Version: 3.0

import requests
import urllib3
import urllib
import shutil
import time
import json
import os
import docker 
import paramiko
import docker
import subprocess
import sys
from datetime import datetime

def e2e_log_header(logfile_name):
    err = ""
    write_to_logs(err, logfile_name)
    err = "    ________  ________    ________"
    write_to_logs(err, logfile_name)
    err = "   /  _____/ /_____   /  /  _____/"
    write_to_logs(err, logfile_name)
    err = "  /  /____   _____/  /  /  /____"
    write_to_logs(err, logfile_name)
    err = " /  _____/  /  _____/  /  _____/"
    write_to_logs(err, logfile_name)
    err = "/  /____   /  /_____  /  /____"
    write_to_logs(err, logfile_name)
    err = "_______/  /________/ / _______/   2024"
    write_to_logs(err, logfile_name)
    err = ""
    write_to_logs(err, logfile_name)
    err = "Author: Brendan O'Connor"
    write_to_logs(err, logfile_name)
    err = "Source Code: https://github.com/boconnor2017"
    write_to_logs(err, logfile_name)
    err = ""
    write_to_logs(err, logfile_name)
    err = ""
    write_to_logs(err, logfile_name)

def e2e_print_header():
    err = ""
    print(err)
    err = "    ________  ________    ________"
    print(err)
    err = "   /  _____/ /_____   /  /  _____/"
    print(err)
    err = "  /  /____   _____/  /  /  /____"
    print(err)
    err = " /  _____/  /  _____/  /  _____/"
    print(err)
    err = "/  /____   /  /_____  /  /____"
    print(err)
    err = "_______/  /________/ / _______/"
    print(err)
    err = ""
    print(err)
    err = "Author: Brendan O'Connor"
    print(err)
    err = "Source Code: https://github.com/boconnor2017"
    print(err)
    err = ""
    print(err)
    err = ""
    print(err)

def hesiod_log_header(logfile_name):
    err = ""
    write_to_logs(err, logfile_name)
    err = "                                    ____                ___"
    write_to_logs(err, logfile_name)
    err = "                                   /___/               /  /"
    write_to_logs(err, logfile_name)
    err = "     ___     ___ __________   _______                 /  /"
    write_to_logs(err, logfile_name)
    err = "    /  /    /  //  _______/  /      /  ________ _____/  / "
    write_to_logs(err, logfile_name)
    err = "   /  /____/  //  /______   /   /__/_ /  __   //  __   /"
    write_to_logs(err, logfile_name)
    err = "  /  _____   //  _______/__/   //   //  / /  //  / /  /"
    write_to_logs(err, logfile_name)
    err = " /  /    /  //  /______ / /   //   //  /_/  //  /_/  /"
    write_to_logs(err, logfile_name)
    err = "/__/    /__//_________//_____//___//_______//_______/"
    write_to_logs(err, logfile_name)
    err = ""
    write_to_logs(err, logfile_name)
    err = "Author: Brendan O'Connor"
    write_to_logs(err, logfile_name)
    err = "Source Code: https://github.com/boconnor2017"
    write_to_logs(err, logfile_name)
    err = ""
    write_to_logs(err, logfile_name)
    err = ""
    write_to_logs(err, logfile_name)

def hesiod_print_header():
    err = ""
    print(err)
    err = "                                    ____                ___"
    print(err)
    err = "                                   /___/               /  /"
    print(err)
    err = "     ___     ___ __________   _______                 /  /"
    print(err)
    err = "    /  /    /  //  _______/  /      /  ________ _____/  / "
    print(err)
    err = "   /  /____/  //  /______   /   /__/_ /  __   //  __   /"
    print(err)
    err = "  /  _____   //  _______/__/   //   //  / /  //  / /  /"
    print(err)
    err = " /  /    /  //  /______ / /   //   //  /_/  //  /_/  /"
    print(err)
    err = "/__/    /__//_________//_____//___//_______//_______/"
    print(err)
    err = ""
    print(err)
    err = "Author: Brendan O'Connor"
    print(err)
    err = "Source Code: https://github.com/boconnor2017"
    print(err)
    err = ""
    print(err)
    err = ""
    print(err)

def write_to_logs(err, logfile_name):
    tstamp = str(datetime.now())
    logfile = open(logfile_name, "a")
    logfile.write(tstamp+": "+err+" \n")
    logfile.close