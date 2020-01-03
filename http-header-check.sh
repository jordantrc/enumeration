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
	echo "Usage: http-header-check.sh [OPTIONS] [https:]host[:port][/url]"
	echo "Valid Options:"
	echo "	-b 				brief output, prints the test result in one line"
	echo "	-s <header>		check for a single header"
	echo "	-n				remove colorized output"
	echo "	-v				verbose output, print the whole HTTP protocol response" 
	echo "					without the content"
	echo "	-t <seconds>	set the timeout for curl, default is 5 seconds"
	exit 1
}

# print_output function
# requires response to be passed as the only argument
print_output() {
	RESPONSE=$1
	STS=$(echo $RESPONSE | grep -i 'strict-transport-security')
	CSP=$(echo $RESPONSE | grep -i 'content-security-policy')
	XSS=$(echo $RESPONSE | grep -i 'x-xss-protection')
	XFR=$(echo $RESPONSE | grep -i 'x-frame-options')
	XCO=$(echo $RESPONSE | grep -i 'x-content-type-options')

	echo -e "$NEU HTTP HEADER STATUS:"

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
}

# print_output_brief function
# requires response to be passed as the only argument
print_output_brief() {
	RESPONSE=$1
	STS=$(echo $RESPONSE | grep -i 'strict-transport-security')
	CSP=$(echo $RESPONSE | grep -i 'content-security-policy')
	XSS=$(echo $RESPONSE | grep -i 'x-xss-protection')
	XFR=$(echo $RESPONSE | grep -i 'x-frame-options')
	XCO=$(echo $RESPONSE | grep -i 'x-content-type-options')

	if [ ${#CSP} -gt 0 ]; then CSP_BOOL=true; else CSP_BOOL=false; fi
	if [ ${#STS} -gt 0 ]; then STS_BOOL=true; else STS_BOOL=false; fi
	if [ ${#XCO} -gt 0 ]; then XCO_BOOL=true; else XCO_BOOL=false; fi
	if [ ${#XFR} -gt 0 ]; then XFR_BOOL=true; else XFR_BOOL=false; fi
	if [ ${#XSS} -gt 0 ]; then XSS_BOOL=true; else XSS_BOOL=false; fi

	echo "CSP: $CSP_BOOL, STS: $STS_BOOL, XCO: $XCO_BOOL, XFR: $XFR_BOOL, XSS: $XSS_BOOL"
}

# get options
if [ "$#" -lt 1 ]; then
	echo "Must provide URL, exiting"
    usage
    exit 1
fi
BRIEF_OUTPUT=false
NO_COLOR=false
VERBOSE=false
TIMEOUT="5"
HEADER="ALL"
while getopts "vs:nbt:" o; do
    case "${o}" in
        b)
            BRIEF_OUTPUT=true
            ;;
		n)
			NO_COLOR=true
			;;
        s)
            HEADER=${OPTARG}
            ;;
		v)
			VERBOSE=true
			;;
		t)
			TIMEOUT=${OPTARG}
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

echo -e "#############################################"
echo -e "$NEU Connecting to $1"
RESPONSE=$($CURL --connect-timeout $TIMEOUT -k -I $1 2>/dev/null)

if $VERBOSE; then
	echo "HTTP RESPONSE:"
	echo "$RESPONSE" | sed 's/^M$//'
fi

# get the HTTP status code
HTTP_STATUS_CODE=$(echo "$RESPONSE" | grep "HTTP/" | cut -d " " -f 2-)
echo -e "$NEU HTTP Status Code: $HTTP_STATUS_CODE"

# print output
if $BRIEF_OUTPUT; then
	print_output_brief $RESPONSE
else
	print_output $RESPONSE

echo -e "#############################################"

exit 0