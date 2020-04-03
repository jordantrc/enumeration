#!/usr/bin/env python3
#
# Usage: query_crt_sh.py <domain> <output file>
#

import csv
import requests
import sys
from bs4 import BeautifulSoup as Soup
from datetime import date


def datefromiso(date_string):
    year, month, day = date_string.split("-")
    date_obj = date(int(year), int(month), int(day))
    return date_obj


def is_expired(logged, invalid):
    today = date.today()
    log_date = datefromiso(logged)
    invalid_date = datefromiso(invalid)

    if invalid_date < log_date:
        result = "yes"
    elif invalid_date < today:
        result = "maybe"  # inconclusive (maybe)
    else:
        result = "no"
    return result
    

def main():
    """main function"""
    domain = sys.argv[1]
    output_file = sys.argv[2]

    field_names = ['date_logged', 'date_valid', 'date_invalid', 'domain', 'issuer', 'expired']
    csv_fd = open(output_file, 'w', newline='')
    csv_writer = csv.DictWriter(csv_fd, fieldnames=field_names)
    csv_writer.writeheader()

    url = "http://crt.sh/?q=%s" % domain

    res = requests.get(url)
    response = res.text

    soup = Soup(response, 'html.parser')
    tables = soup.find_all('table')
    cert_table = tables[2]
    rows = cert_table.find_all('tr')
    for r in rows[1:]:
        elems = r.find_all('td')
        date_logged = elems[1].get_text()
        date_valid = elems[2].get_text()
        date_invalid = elems[3].get_text()
        issuer = elems[5].get_text() 
        domains = elems[4].get_text(separator=";").split(";")
        # determine expiration status
        expired = is_expired(date_logged, date_invalid)
        for d in domains:
            row = {
                'date_logged': date_logged,
                'date_valid': date_valid,
                'date_invalid': date_invalid,
                'domain': d,
                'issuer': issuer,
                'expired': expired
            }
            csv_writer.writerow(row)

        print("%s, %s, %s, %s, %s" % (date_logged, date_valid, date_invalid, domains, issuer))
    csv_fd.close()


if __name__ == "__main__":
    main()