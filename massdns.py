#!/usr/bin/env python3
"""
Author: Jordan Chadwick
Borrowed heavily from Patrik Hudak:
https://0xpatrik.com/subdomain-enumeration-2019/

Usage:
massdns.py <path to resolvers file> <domain>
"""

import json
import subprocess
import sys

def _exec_and_readlines(cmd, domain):

    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, stdin=subprocess.PIPE)
    stdout, stderr = proc.communicate(input=domain)

    return [j.decode('utf-8').strip() for j in stdout.splitlines() if j != b'\n']


def main():
    
    RESOLVERS_PATH = sys.argv[1]
    DOMAIN = sys.argv[2]
    massdns_cmd = [
        'massdns',
        '-s', '15000',
        '-t', 'A',
        '-o', 'J',
        '-r', RESOLVERS_PATH,
        '--flush'
    ]

    processed = []

    for line in _exec_and_readlines(massdns_cmd, DOMAIN):
        if not line:
            continue

        processed.append(json.loads(line.strip()))

    for p in processed:
        print(p)

if __name__ == "__main__":
    main()
