#!/usr/bin/env python3
"""
Author: Jordan Chadwick
Borrowed heavily from Patrik Hudak:
https://0xpatrik.com/subdomain-enumeration-2019/

Requires massdns, available here:
https://github.com/blechschmidt/massdns

A reliable list of public DNS resolvers is available here:
https://public-dns.info/nameservers.txt

Usage:
massdns.py <path to resolvers file> <domain> <sub-domain wordlist>
"""

import json
import subprocess
import sys

def _exec_and_readlines(cmd, domains):

    domains = bytes('\n'.join(domains), 'ascii')
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, stdin=subprocess.PIPE)
    stdout, stderr = proc.communicate(input=domains)

    return [j.decode('utf-8').strip() for j in stdout.splitlines() if j != b'\n']


def main():
    
    RESOLVERS_PATH = sys.argv[1]
    DOMAIN = sys.argv[2]
    WORDLIST = sys.argv[3]
    massdns_cmd = [
        'massdns',
        '-s', '15000',
        '-t', 'A',
        '-o', 'J',
        '-r', RESOLVERS_PATH,
        '--flush'
    ]

    # get the contents of the wordlist and prepend to the domain
    domains = []
    with open(WORDLIST, 'r') as word_fd:
        lines = word_fd.read().splitlines()
        for l in lines:
            l.strip()
            domains.append("{}.{}\n".format(l, DOMAIN))

    processed = []

    for line in _exec_and_readlines(massdns_cmd, domains):
        if not line:
            continue

        processed.append(json.loads(line.strip()))

    for p in processed:
        print(p)

if __name__ == "__main__":
    main()
