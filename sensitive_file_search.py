#!/bin/python3
#
# Usage:
# sensitive_file_search.py [OPTIONS] [files|STDIN]
# Valid options:
# 	-f:		format - supported values include:
#			smbmap
#
# If no format is specified, assumes one file name per line
#
# Searches the file listing provided for sensitive filenames.
# If no file names are provided, reads from STDIN.
#

import argparse
import os
import sys

FILENAME_KEYWORDS = [
    'password',
    'credentials',
    'creds',
    'user',
    'account',
    'acct',
    'passwd',
    'administrator',
    'admin',
    'root',
    'secret',
    'key',
    'ssn',
    'dob',
    'credit',
    'debit',
    'vhd',
    'vmdk',
    'vhdx'
]

SUPPORTED_FORMATS = [
    'smbmap',
]


def parse_file_entry(entry, file_format):
    """parses a file entry given the format"""
    # smbmap example:
    # host:10.1.1.1, privs:READ_ONLY, isDir:f, name:dir1\dir2\file1234.txt, fileSize:1698, date:Tue Feb 14 19:43:46 2017
    # host:10.1.1.1, privs:READ_ONLY, isDir:d, name:dir1\dir2\dir3, fileSize:0, date:Tue Feb 14 19:43:46 2017
    if format == "smbmap":
        fields = entry.split(", ")
        file_path_raw = fields[3]
        file_path = file_path_raw.split(":")[1]
        file_name = os.path.basename(file_path)
    elif format is None:
        file_name = entry
    
    return file_name


def keyword_search(filename, fs_list, file_format=None):
    """Search the filesystem list for keywords."""
    matching_files = []
    for i, f in enumerate(fs_list):
        file_name = parse_file_entry(f, file_format)
        for k in FILENAME_KEYWORDS:
            if k in file_name.lower():
                extension = '(none)'
                if "." in file_name:
                    extension = file_name.split('.')[-1].lower()
                matching_files.append([filename, i, file_name, extension])
                break

    return matching_files


def main():
    """Main function."""

    parser = argparse.ArgumentParser()
    parser.add_argument("-f", help="Format specification")
    parser.add_argument("files", nargs="*", help="Files containing filesystem listings.")
    args = parser.parse_args()

    files = args.files
    file_format = args.f
    filesystem_list = []
    matching_files = []

    if file_format is not None:
        if file_format not in SUPPORTED_FORMATS:
            print("[-] unsupported format %s" % file_format)
            sys.exit(1)

    # if files is empty, read from STDIN
    if len(files) == 0:
        print("Enter filesystem contents, one file per line:")
        filesystem_list = sys.stdin.readlines()
        matching_files = keyword_search('stdin', filesystem_list)
    else:
        print("Searching the following files:")
        for f in files:
            print(f)
            if os.path.isfile(f):
                with open(f, 'r') as fd:
                    filesystem_list = fd.readlines()
                matching_files.extend(keyword_search(f, filesystem_list, file_format=file_format))
            else:
                print("Invalid file %s" % f)

    # print the results
    print("\n\nPOTENTIAL SENSITIVE FILES OR FOLDERS:")
    print("Source file\t\tLine number\t\tFile name")
    for f in matching_files:
        print("%s\t\t%s\t\t%s" % (f[0], f[1], f[2]))


if __name__ == "__main__":
    main()
