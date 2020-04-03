#!/usr/bin/env python3
#
# Usage: query_crt_sh.py <domain>
#

import requests
import sys
from bs4 import BeautifulSoup as Soup
from datetime import date


def main():
    """main function"""
    domain = sys.argv[1]
    url = "http://crt.sh/?q=%s" % domain

    res = requests.get(url)
    response = res.text

    soup = Soup(response, 'html.parser')
    tables = soup.find_all('table')
    cert_table = tables[2]
    rows = cert_table.find_all('tr')
    print("Date Logged, Date Valid, Date Invalid, Domains, Issuer")
    for r in rows[1:]:
        elems = r.find_all('td')
        date_logged = elems[1].get_text()
        date_valid = elems[2].get_text()
        date_invalid = elems[3].get_text()
        for br in elems[4].find('br'):
            br.replace_with("\n")
        domains = elems[4].get_text().split("\n")
        issuer = elems[5].get_text()
        print("%s, %s, %s, %s, %s" % (date_logged, date_valid, date_invalid, domains, issuer))


if __name__ == "__main__":
    main()