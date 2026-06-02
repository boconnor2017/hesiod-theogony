# Hesiod File Management
# Author: Brendan O'Connor
# Date: June 2026
# Version: 4.0

# Import Hesiod Libraries (Standard Imports)
from python_lib import standard_imports as std

def append_text_to_file(text, file_name):
    new_file = open(file_name, "a")
    new_file.writelines(text)
    new_file.close()

def check_if_file_exists(foobar):
    file_path = std.Path(foobar)
    if file_path.is_file():
        return 1
    else:
        return 0

def copy_file_from_srcdir_to_destdir(source_file_path, destination_file_path):
    std.shutil.copy(source_file_path, destination_file_path)

def download_content_from_url_into_var(url):
    web_content = std.urllib.request.urlopen(url)
    return(web_content)

def download_file_from_url(url, filename):
    std.urllib.request.urlretrieve(url, filename)

def populate_file_from_var(file_name, var_as_str):
    with open(file_name, 'w+') as fh:
        fh.write(var_as_str)

def populate_var_from_file(file_name):
    with open(file_name) as file:
        file_txt = file.read()
        return file_txt


