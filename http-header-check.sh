#!/bin/bash
#
# Script to detect presence of HTTP security headers for a web application
#
# Usage: http-header-check.sh [OPTIONS] [https:]host[:port][\url]
# Valid Options:
#	-b 				brief output, prints a result per-line
#	-s <header>		check for a single header
#	-n				remove colorized output

usage() {
	echo "Usage: http-header-check.sh [OPTIONS] [https:]host[:port][\url]"
	echo "Valid Options:"
	echo "	-b 				brief output, prints a result per-line"
	echo "	-s <header>		check for a single header"
	echo "	-n				remove colorized output"
	exit 1
}

# get options
if [ "$#" -lt 1 ]; then
	echo "Must provide URL, exiting"
    usage
    exit 1
fi
SHORT_OUTPUT=false
NO_COLOR=false
HEADER='ALL'
while getopts "snh:" o; do
    case "${o}" in
        b)
            SHORT_OUTPUT=true
            ;;
		n)
			NO_COLOR=true
			;;
        s)
            HEADER=${OPTARG}
            ;;
        *)
            usage
            ;;
    esac
done
shift $((OPTIND-1))

# fancy schmancy colorized output stuff
RED='\033[0;31m'
NC='\033[0m' # No Color
GREEN='\033[0;32m'
YELLOW='\033[1;33m'

if $NO_COLOR; then
	RED=""
	GREEN=""
	YELLOW=""
	NC=""
fi

# sigils to be used in output
POS="${GREEN}[+]${NC}"
NEG="${RED}[-]${NC}"
NEU="${YELLOW}[*]${NC}"

CURL="/usr/bin/curl"

echo -e "$NEU Connecting to $1"
RESULT=$($CURL -v -k --silent $1 2>&1 1>/dev/null)

# get the HTTP status code
HTTP_STATUS_CODE=$(echo "$RESULT" | grep "< HTTP/" | cut -d " " -f 3,4)
echo -e "$NEU HTTP Status Code: $HTTP_STATUS_CODE"

#echo -e "$NEU Checking the response for the HTTP Security Headers"
# check for the headers
STS=$(echo $RESULT | grep -i 'strict-transport-security')
CSP=$(echo $RESULT | grep -i 'content-security-policy')
XSS=$(echo $RESULT | grep -i 'x-xss-protection')
XFR=$(echo $RESULT | grep -i 'x-frame-options')
XCO=$(echo $RESULT | grep -i 'x-content-type-options')

# print output
echo -e "$NEU RESULTS:"

if [ ${#CSP} -gt 0 ]; then
	echo -e "$POS Content-Security-Policy header found"
else
	echo -e "$NEG Content-Security-Policy header missing"
fi

if [ ${#STS} -gt 0 ]; then
	echo -e "$POS Strict-Transport-Security header found"
else
	echo -e "$NEG Strict-Transport-Security header missing"
fi

if [ ${#XCO} -gt 0 ]; then
	echo -e "$POS X-Content-Type-Options header found"
else
	echo -e "$NEG X-Content-Type-Options header missing"
fi

if [ ${#XFR} -gt 0 ]; then
	echo -e "$POS X-Frame-Options header found"
else
	echo -e "$NEG X-Frame-Options header missing"
fi

if [ ${#XSS} -gt 0 ]; then
	echo -e "$POS X-XSS-Protection header found"
else
	echo -e "$NEG X-XSS-Protection header missing"
fi

exit 0