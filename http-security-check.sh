#!/bin/bash
#
# Script to detect presence of HTTP security headers for a web application
#
# See usage function for details regarding options and arguments.

usage() {
    echo "Usage: http-header-check.sh [OPTIONS] [http://|https://]host[:port][/url]"
    echo "Valid Options:"
    echo "  -b              brief output, prints the test result in one line"
    echo "  -s <header>     check for a single security header in the response"
    echo "  -n              remove colorized output"
    echo "  -v              verbose output, print the whole HTTP protocol response" 
    echo "                  without the content"
    echo "  -c              certificate file for client authentication"
    echo "  -p              [optional] password for the certificate file, if none is provided and the"
    echo "                  cert requires it, a prompt will appear"
    echo "  -t <seconds>    set the timeout for curl, default is 5 seconds"
    echo "  -k              check all cookies for security flags (secure, httponly)"
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
    if [ "${#errors}" -gt 0 ]; then
        echo -e "$neg Errors encountered:"
        echo -e "$errors"
    else
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

        if [ ${#insecure_cookies} -gt 0 ]; then
            echo -e "Insecure Cookies:"
            echo -e "$insecure_cookies"
        fi
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
    if [ "${#errors}" -gt 0 ]; then
        errors=$(echo "$errors" | tr '\n' '; ')
        output_string="$url errors: $errors"
    else
        if [ ${#csp} -gt 0 ]; then csp_bool=true; else csp_bool=false; fi
        if [ ${#sts} -gt 0 ]; then sts_bool=true; else sts_bool=false; fi
        if [ ${#xco} -gt 0 ]; then xco_bool=true; else xco_bool=false; fi
        if [ ${#xfr} -gt 0 ]; then xfr_bool=true; else xfr_bool=false; fi
        if [ ${#xss} -gt 0 ]; then xss_bool=true; else xss_bool=false; fi

        insecure_cookies_brief=""
        if [ ${#insecure_cookies} -gt 0 ]; then
            insecure_cookies_brief=$(echo "$insecure_cookies" | tr '\n' '; ')
        fi

        output_string="$url $http_status_code CSP:$csp_bool STS:$sts_bool XCO:$xco_bool XFR:$xfr_bool XSS:$xss_bool"

        if [ ${#insecure_cookies_brief} -gt 0 ]; then
            output_string+=" Insecure Cookies: $insecure_cookies_brief"
        fi
    fi

    printf "%s\n" "$output_string"
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
cookie_check=false
timeout="5"
header="ALL"
certificate_file=""
certificate_password=""
while getopts "vs:nbkt:c:p:m:h:" o; do
    case "${o}" in
        b)
            brief_output=true
            ;;
        c)
            certificate_file=${OPTARG}
            ;;
        k)
            cookie_check=true
            ;;
        n)
            no_color=true
            ;;
        p)
            certificate_password=${OPTARG}
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

# add a --cert option if specified
if [ ${#certificate_file} -gt 0 ]; then
    if [ ${#certificate_password} -gt 0 ]; then
        certificate_option="--cert $certificate_file:$certificate_password"
    else
        certificate_option="--cert $certificate_file"
    fi
else
    certificate_option=""
fi

curl="/usr/bin/curl"
response=$($curl $certificate_option -sS --connect-timeout $timeout -k -I $url 2>&1)
curl_exit_code="$?"

# curl error handling
errors=""
if [ "$curl_exit_code" -ne "0" ]; then
    errors=$(echo "$response" | cut -d ":" -f 2- | sed 's/^[[:blank:]]*//;s/[[:blank:]]*$//')
fi

http_status_code=$(echo "$response" | grep "HTTP/" | cut -d " " -f 2)

# check for the HTTP security headers
sts=$(echo "$response" | grep -i 'strict-transport-security')
csp=$(echo "$response" | grep -i 'content-security-policy')
xss=$(echo "$response" | grep -i 'x-xss-protection')
xfr=$(echo "$response" | grep -i 'x-frame-options')
xco=$(echo "$response" | grep -i 'x-content-type-options')

# check for cookie security flags if desired
insecure_cookies=""
if $cookie_check; then
    insecure_cookies=$(echo "$response" | grep -i 'Set-Cookie' | \
        grep -Eiv '(;\s*secure;\s*httponly\s*$|;\s*httponly;\s*secure\s*$)')
fi

# print output
if $brief_output; then
    print_output_brief
else
    print_output
fi

exit 0
