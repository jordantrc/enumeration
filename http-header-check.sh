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

#######################################
# print detailed output
# Globals:
#	csp, sts, xco, xfr, xss
#	http_status_code
#   response
#	url
# Arguments:
#   None
# Returns:
#   None
#######################################
print_output() {
	echo "#################################################"
	echo -e "$neu URL: $url"
	echo -e "$neu HTTP Status Code: $http_status_code"
	
	if $verbose; then
		echo "HTTP Response Headers:"
		echo "$response" | sed 's/^M$//'
	fi

	echo -e "$neu HTTP Header Status:"
	if [ ${#csp} -gt 0 ]; then
		echo -e "$pos Content-Security-Policy header found"
	else
		echo -e "$neg Content-Security-Policy header missing"
	fi

	if [ ${#sts} -gt 0 ]; then
		echo -e "$pos Strict-Transport-Security header found"
	else
		echo -e "$neg Strict-Transport-Security header missing"
	fi

	if [ ${#xco} -gt 0 ]; then
		echo -e "$pos X-Content-Type-Options header found"
	else
		echo -e "$neg X-Content-Type-Options header missing"
	fi

	if [ ${#xfr} -gt 0 ]; then
		echo -e "$pos X-Frame-Options header found"
	else
		echo -e "$neg X-Frame-Options header missing"
	fi

	if [ ${#xss} -gt 0 ]; then
		echo -e "$pos X-XSS-Protection header found"
	else
		echo -e "$neg X-XSS-Protection header missing"
	fi

	echo "#################################################"
}

#######################################
# print brief output
# Globals:
#	csp, sts, xco, xfr, xss
#	http_status_code
#   response
#	url
# Arguments:
#   None
# Returns:
#   None
#######################################
print_output_brief() {
	if [ ${#csp} -gt 0 ]; then csp_bool=true; else csp_bool=false; fi
	if [ ${#sts} -gt 0 ]; then sts_bool=true; else sts_bool=false; fi
	if [ ${#xco} -gt 0 ]; then xco_bool=true; else xco_bool=false; fi
	if [ ${#xfr} -gt 0 ]; then xfr_bool=true; else xfr_bool=false; fi
	if [ ${#xss} -gt 0 ]; then xss_bool=true; else xss_bool=false; fi

	printf "%s\n" "$url $http_status_code CSP:$csp_bool STS:$sts_bool XCO:$xco_bool XFR:$xfr_bool XSS:$xss_bool"
}

# get options
if [ "$#" -lt 1 ]; then
	echo "Must provide URL, exiting"
    usage
    exit 1
fi

brief_output=false
no_color=false
verbose=false
timeout="5"
header="ALL"
while getopts "vs:nbt:" o; do
    case "${o}" in
        b)
            brief_output=true
            ;;
		n)
			no_color=true
			;;
        s)
            header=${OPTARG}
            ;;
		v)
			verbose=true
			;;
		t)
			timeout=${OPTARG}
			;;
        *)
            usage
            ;;
    esac
done
shift $((OPTIND-1))

url="$1"

# fancy schmancy colorized output stuff
red='\033[0;31m'
nc='\033[0m' # No Color
green='\033[0;32m'
yellow='\033[1;33m'

if $no_color; then
	red=""
	green=""
	yellow=""
	nc=""
fi

# sigils to be used in output
pos="${green}[+]${nc}"
neg="${red}[-]${nc}"
neu="${yellow}[*]${nc}"

curl="/usr/bin/curl"
response=$($curl --connect-timeout $timeout -k -I $url 2>/dev/null)

# get the HTTP status code
http_status_code=$(echo "$response" | grep "HTTP/" | cut -d " " -f 2)

# check for the HTTP security headers
sts=$(echo $response | grep -i 'strict-transport-security')
csp=$(echo $response | grep -i 'content-security-policy')
xss=$(echo $response | grep -i 'x-xss-protection')
xfr=$(echo $response | grep -i 'x-frame-options')
xco=$(echo $response | grep -i 'x-content-type-options')

# print output
if $brief_output; then
	print_output_brief
else
	print_output
fi

exit 0
