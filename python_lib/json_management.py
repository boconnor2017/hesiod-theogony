# Hesiod JSON Management
# Author: Brendan O'Connor
# Date: June 2026
# Version: 4.0

# Import Hesiod Libraries (Standard Imports)
from python_lib import standard_imports as std

# Downloads json as a file
def download_json_file_from_url(url, json_filename):
    # Syntax url: "https://domain.com/foo/bar/something.json"
    # Syntax json_filename: "what_I_want_to_call_it.json"
    std.urllib.request.urlretrieve(url, json_filename)

def download_json_to_var_from_url(url):
    # Syntax url: "https://domain.com/foo/bar/something.json"
    json_web = std.urllib.request.urlopen(url)
    # Converts the raw binary into a string
    json_binvar = json_web.read()
    json_stringvar = json_binvar.decode("utf-8")
    return json_stringvar

# Dump converts a JSON python object to string
def dump_json(json_python_obj):
    json_stringvar = std.json.dumps(json_python_obj)
    return json_stringvar

# Dump converts a JSON python object and writes it to JSON file
def dump_json_to_file(json_python_obj, json_filename):
    json_file = open(json_filename, "w")
    json_dump = std.json.dump(json_python_obj, json_file, indent = 6)

# Returns the keys from a JSON python object
def get_keys_from_json(json_python_obj):
    json_keys = []
    for key, value in json_python_obj.items():
        json_keys.append(key)
    return json_keys

# Loading converts a JSON string to a python object
def load_json_variable(json_stringvar):
    json_python_obj = std.json.loads(json_stringvar)
    return json_python_obj

# Populates variable from contents of JSON file
def populate_var_from_json_file(json_dir, json_filename):
    # Syntax json_dir: "/foo/bar"
    # Syntax json_filename: "something.json"
    # Syntax json_file_full: "/foo/bar/something.json"
    json_file_full = json_dir+"/"+json_filename
    # Creates variable vcf_json_raw with contents from json file
    #json_raw = libgen.populate_var_from_file(json_file_full)
    with open(json_file_full) as file:
        json_stringvar = file.read()
        return json_stringvar