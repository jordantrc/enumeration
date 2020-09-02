#!/usr/bin/env python3
#
# sslscan_report.py
# Creates a CSV-formatted report from a sslscan
# XML-formatted report. The ouput file is named
# sslscan_YYYYMMDD_HHMMSS.csv. The timestamp is
# based on the current date and time.
# 
# Usage:
# sslscan_report.py <input file>

import argparse
import csv
import os
import xml.etree.ElementTree as ET
from datetime import datetime


def minimum_tls_version(supported_protocols):
    """Returns the minimum supported TLS version"""
    result = None
    tls_versions = ['ssl2', 'ssl3', 'tls10', 'tls11', 'tls12', 'tls13']
    tls_versions_pretty = ['sslv2', 'sslv3', 'tls 1.0', 'tls 1.1', 'tls 1.2', 'tls 1.3']

    for i, v in enumerate(tls_versions):
        if supported_protocols[v] == "1":
            result = tls_versions_pretty[i]
            break
    
    return result


def minimum_cipher_strength(supported_ciphers):
    """Returns the minimum supported cipher strength"""
    # find lowest cipher bits supported
    lowest_cipher_bits = 4000000000  # suitably large number
    for c in supported_ciphers:
        cipher_bits = int(c['bits'])
        if cipher_bits < lowest_cipher_bits:
            lowest_cipher_bits = cipher_bits
    
    # find the highest cipher order with the lowest cipher bits
    # assumes the supported_ciphers list is already sorted
    # by cipher order
    highest_order_lowest_bit_cipher = None
    for c in supported_ciphers:
        cipher_bits = int(c['bits'])
        if cipher_bits == lowest_cipher_bits:
            highest_order_lowest_bit_cipher = c
    
    result = None
    if highest_order_lowest_bit_cipher is not None:
        result = "%s bit %s" % (highest_order_lowest_bit_cipher['bits'], highest_order_lowest_bit_cipher['cipher'])

    return result


def main():
    """main function"""
    parser = argparse.ArgumentParser()
    parser.add_argument("input_file", nargs=1, help="input file to read")
    args = parser.parse_args()

    input_file = args.input_file[0]
    assert os.path.isfile(input_file), "%s does not exist or is not a file" % input_file

    # read xml data from file
    tree = ET.parse(input_file)
    root = tree.getroot()
    results = list(root)

    # traverse results and create dictionary
    all_scans = []
    for r in results:
        scan = {
            'host': None, 
            'sniname': None, 
            'port': None,
            'minimum_tls_version': None,
            'heartbleed_vulnerable': None,
            'minimum_cipher_strength': None,
            'signature_algorithm': None,
            'public_key_entropy': None,
            'certificate_inception': None,
            'certificate_expiration': None,
            'validity_days': None,
            'certificate_expired': None,
            'self_signed': None
            }
        protocol_support = {
            'ssl2': None,
            'ssl3': None,
            'tls10': None,
            'tls11': None,
            'tls12': None,
            'tls13': None
        }
        accepted_ciphers = []
        scan['host'] = r.attrib['host']
        scan['sniname'] = r.attrib['sniname']
        scan['port'] = r.attrib['port']

        scan_elements = list(r)

        # parse the scan tree
        for e in scan_elements:
            #print(e)
            cipher_order = 0
            if e.tag == 'protocol':
                tls_version = e.attrib['type'] + e.attrib['version'].replace('.', '')
                protocol_support[tls_version] = e.attrib['enabled']
            elif e.tag == 'heartbleed':
                scan['heartbleed_vulnerable'] = e.attrib['vulnerable']
            elif e.tag == 'cipher' and e.attrib['status'] in ['preferred', 'accepted']:
                cipher = {
                    'sslversion': e.attrib['sslversion'],
                    'bits': e.attrib['bits'],
                    'cipher': e.attrib['cipher'],
                    'strength': e.attrib['strength'],
                    'order': cipher_order 
                }
                accepted_ciphers.append(cipher)
                cipher_order += 1
            elif e.tag == 'certificates':
                cert = list(e)
                #print("\t%s" % cert)
                if len(cert) > 0:
                    cert_elements = list(cert[0])
                else:
                    cert_elements = []
                for f in cert_elements:
                    #print("\t\t%s" % f)
                    if f.tag == "signature-algorithm":
                        scan['signature_algorithm'] = f.text
                    elif f.tag == "pk":
                        scan['public_key_entropy'] = f.attrib['bits']
                    elif f.tag == "self-signed":
                        scan['self_signed'] = f.text
                    elif f.tag == "not-valid-before":
                        inception = datetime.strptime(f.text, "%b %d %H:%M:%S %Y %Z")
                        scan['certificate_inception'] = inception.strftime("%m/%d/%y")
                    elif f.tag == "not-valid-after":
                        expiration = datetime.strptime(f.text, "%b %d %H:%M:%S %Y %Z")
                        validity_days = (expiration - inception).days
                        scan['certificate_expiration'] = expiration.strftime("%m/%d/%y")
                        scan['validity_days'] = validity_days
                    elif f.tag == "expired":
                        scan['certificate_expired'] = f.text
            
        # set minimum cipher and minimum tls
        scan['minimum_tls_version'] = minimum_tls_version(protocol_support)
        scan['minimum_cipher_strength'] = minimum_cipher_strength(accepted_ciphers)
        all_scans.append(scan)

    # create csv file
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_output = "sslscan_%s.csv" % timestamp
    fieldnames = all_scans[0].keys()
    with open(csv_output, 'w', newline='') as csv_fd:
        csvwriter = csv.DictWriter(csv_fd, fieldnames=fieldnames, dialect='excel')
        csvwriter.writeheader()
        for s in all_scans:
            csvwriter.writerow(s)
    
    print("[+] %d scan results written to %s" % (len(all_scans), csv_output))


if __name__ == "__main__":
    main()
