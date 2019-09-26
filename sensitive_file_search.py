#!/bin/python3
#
# Usage:
# sensitive_file_search.py [files|STDIN]
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
    'debit'
]


def keyword_search(filename, fs_list):
    """Search the filesystem list for keywords."""
    matching_files = []
    for i, f in enumerate(fs_list):
        for k in FILENAME_KEYWORDS:
            if k in f.lower():
                extension = '(none)'
                if "." in f:
                    extension = f.split('.')[-1].lower()
                matching_files.append([filename, i, f, extension])
                break

    return matching_files


def main():
    """Main function."""

    parser = argparse.ArgumentParser()
    parser.add_argument("files", nargs="*", help="Files containing filesystem listings.")
    args = parser.parse_args()

    files = args.files
    filesystem_list = []
    matching_files = []

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
                matching_files.extend(keyword_search(f, filesystem_list))
            else:
                print("Invalid file %s" % f)

    # print the results
    print("\n\nPOTENTIAL SENSITIVE FILES OR FOLDERS:")
    print("Source file\t\tLine number\t\tFile name")
    for f in matching_files:
        print("%s\t\t%s\t\t%s" % (f[0], f[1], f[2]))


if __name__ == "__main__":
    main()
