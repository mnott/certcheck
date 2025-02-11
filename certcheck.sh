#!/usr/bin/env bash

###############################################################################
# certificate-check.sh
#
# Checks X.509 certificates in either:
#   - PEM format (with "-----BEGIN CERTIFICATE-----"), or
#   - PKCS#12 format (.p12/.pfx).
#
# Can check:
#   - Single certificate file
#   - All certificates in a directory
#   - Files matching specified patterns
#
# Exit codes:
#   0 - All certificates are valid and not near expiry
#   1 - Error in script execution
#   2 - At least one certificate is expired or near expiry (< 30 days)
###############################################################################

# ANSI color codes
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m'

# Debug flag (set to 1 to enable debug messages)
DEBUG=0
debug() { [[ $DEBUG -eq 1 ]] && echo "DEBUG: $*" >&2; }

# Global variables for tracking overall status
GLOBAL_EXIT_CODE=0

# Usage message
usage() {
    echo "Usage: $0 [options] <certificate-file(s)>"
    echo
    echo "Options:"
    echo "  -h, --help            Display this help message and exit."
    echo "  -c, --ca-file <file>  Specify a custom Root CA file for chain verification."
    echo "  -d, --dir <dir>       Check all certificate files in specified directory."
    echo "  -p, --pattern <pat>   Check files matching pattern (e.g., '*.pem,*.p12')."
    echo "  -s, --stdin           Read certificate from stdin."
    echo "  -n, --chain <name>    Check certificate chain from keychain by common name."
    echo
    echo "Examples:"
    echo "  $0 cert.pem                         # Check single file"
    echo "  $0 -d /path/to/certs                # Check all certs in directory"
    echo "  $0 -p '*.pem,*.p12'                 # Check files matching patterns"
    echo "  $0 -c /path/to/rootCA.pem cert.p12  # Check with custom CA"
    echo "  $0 -n \"I052341\"                   # Check full chain from keychain"
    exit 1
}

###############################################################################
# parse_single_cert
#
#   Takes the text of a single certificate ("Certificate: ...\n   Subject: ...")
#   and prints Subject, Issuer, NotBefore, NotAfter, and expiry status.
###############################################################################
parse_single_cert() {
    local cert_text="$1"

    # Extract lines directly using sed
    local subj iss nb na
    subj=$(echo "$cert_text" | sed -n 's/^[[:space:]]*Subject:[[:space:]]*//p')
    iss=$(echo "$cert_text"  | sed -n 's/^[[:space:]]*Issuer:[[:space:]]*//p')
    nb=$(echo "$cert_text"   | sed -n 's/^[[:space:]]*Not Before:[[:space:]]*//p')
    na=$(echo "$cert_text"   | sed -n 's/^[[:space:]]*Not After :[[:space:]]*//p')

    # Calculate days remaining using Perl
    local days_remaining
    days_remaining=$(
        perl -e '
            use Time::Local;
            my $date_str = $ARGV[0];
            if ($date_str =~ /([A-Za-z]+)\s+(\d+)\s+(\d+):(\d+):(\d+)\s+(\d+)/) {
                my %months = (
                    Jan=>0,Feb=>1,Mar=>2,Apr=>3,May=>4,Jun=>5,
                    Jul=>6,Aug=>7,Sep=>8,Oct=>9,Nov=>10,Dec=>11
                );
                my $end = timegm($5, $4, $3, $2, $months{$1}, $6);
                my $now = time();
                print int(($end - $now) / 86400);
            }
        ' "$na"
    )

    # Determine Cert type: Root vs. Intermediate
    local certType="INTERMEDIATE"
    [[ "$subj" == "$iss" ]] && certType="ROOT"

    # Print certificate information
    printf "  %-12s %s\n" "Subject:"    "$subj"
    printf "  %-12s %s\n" "Issuer:"     "$iss"
    printf "  %-12s %s\n" "Not Before:" "$nb"
    printf "  %-12s %s\n" "Not After:"  "$na"
    printf "  %-12s %s\n" "Type:"       "$certType"

    # Print expiry status with color coding
    printf "  %-12s " "Expiry:"
    if [ -z "$days_remaining" ]; then
        printf "%b\n" "${RED}⚠️  Unable to parse expiry date!${NC}"
    elif [ "$days_remaining" -lt 0 ]; then
        printf "%b\n" "${RED}🛑 EXPIRED ${days_remaining#-} days ago${NC}"
    elif [ "$days_remaining" -lt 30 ]; then
        printf "%b\n" "${RED}🛑 Will expire in $days_remaining days${NC}"
    elif [ "$days_remaining" -lt 90 ]; then
        printf "%b\n" "${YELLOW}⚠️ Will expire in $days_remaining days${NC}"
    else
        printf "%b\n" "${GREEN}✅ Valid for $days_remaining more days${NC}"
    fi

    # Update global exit code if certificate is expired or near expiry
    if [ -z "$days_remaining" ] || [ "$days_remaining" -lt 30 ]; then
        GLOBAL_EXIT_CODE=2
    fi
}

###############################################################################
# parse_certs_info
#
#   Given the text output of a multi-cert chain (from "openssl pkcs7 -print_certs -text -noout"),
#   split into individual certificate blocks and call parse_single_cert.
###############################################################################
parse_certs_info() {
    local all_output="$1"
    local in_cert=0
    local cert_buffer=""
    cert_count=0  # Global variable to track the number of certificates

    while IFS= read -r line; do
        # Look for a line that starts with "Certificate:"
        if [[ "$line" =~ ^Certificate: ]]; then
            # If we were already in a cert block, parse it
            if ((in_cert)) && [ -n "$cert_buffer" ]; then
                ((cert_count++))
                echo "Certificate #$cert_count:"
                parse_single_cert "$cert_buffer"
                echo "---------------------------"
                cert_buffer=""
            fi
            in_cert=1
        fi
        # Accumulate lines if we are within a certificate block
        if ((in_cert)); then
            # Skip any lines that start with "-----BEGIN CERTIFICATE-----" or "-----END CERTIFICATE-----"
            if [[ "$line" =~ ^-----BEGIN\ CERTIFICATE-----$ ]] || [[ "$line" =~ ^-----END\ CERTIFICATE-----$ ]]; then
                continue
            fi
            cert_buffer+="$line"$'\n'
        fi
    done <<< "$all_output"

    # Handle final block, if any
    if ((in_cert)) && [ -n "$cert_buffer" ]; then
        ((cert_count++))
        echo "Certificate #$cert_count:"
        parse_single_cert "$cert_buffer"
        echo "---------------------------"
    fi
}

###############################################################################
# verify_chain
#
#   Verifies the chain in PEM format.
#   If a custom Root CA file is provided, it uses that for verification.
###############################################################################
verify_chain() {
    local cert="$1"
    local ca_file="$2"
    local verify_output

    # First try verifying with just the certificates in the file
    verify_output=$(openssl verify -untrusted "$cert" "$cert" 2>&1)
    if [ $? -eq 0 ]; then
        printf "%b\n" "${GREEN}✅ Chain verification successful (using certificates in file)${NC}"
        return 0
    fi

    # If that fails and we have a custom CA file, try with that
    if [ -n "$ca_file" ] && [ -f "$ca_file" ]; then
        verify_output=$(openssl verify -CAfile "$ca_file" -untrusted "$cert" "$cert" 2>&1)
        if [ $? -eq 0 ]; then
            printf "%b\n" "${GREEN}✅ Chain verification successful (using provided CA file)${NC}"
            return 0
        fi
    fi

    # Finally, try with the system's CA store
    verify_output=$(openssl verify -no-CApath "$cert" 2>&1)
    if [ $? -eq 0 ]; then
        printf "%b\n" "${GREEN}✅ Chain verification successful (using system CA store)${NC}"
        return 0
    fi

    # If all verification attempts failed, provide detailed error message
    if echo "$verify_output" | grep -q "unable to get local issuer certificate"; then
        printf "%b\n" "${RED}🛑 Missing intermediate certificate in chain (not found in file or system CA store)${NC}"
    elif echo "$verify_output" | grep -q "self signed certificate"; then
        printf "%b\n" "${YELLOW}⚠️  Self-signed certificate (typical for root CA)${NC}"
    else
        printf "%b\n" "${RED}🛑 Chain verification failed: $verify_output${NC}"
    fi
    return 1
}

###############################################################################
# parse_cert_info
#
#   Takes the text of a single certificate and prints Subject, Issuer,
#   NotBefore, NotAfter, and expiry status.
###############################################################################
parse_cert_info() {
    local cert_text="$1"
    cert_count=1  # Set to 1 since we're processing a single certificate
    echo "Certificate #1:"
    parse_single_cert "$cert_text"
    echo "---------------------------"
}

# Function to process PKCS#12 files
process_pkcs12() {
    local file="$1"
    local tempPem="/tmp/certcheck_temp_$$.pem"
    trap 'rm -f "$tempPem"' EXIT

    # Extract all certificates (both CA and client certs)
    # Use -chain to ensure we get the complete certificate chain
    if ! openssl pkcs12 -in "$file" -nokeys -nodes -chain -out "$tempPem" 2>/dev/null; then
        echo "Error: Failed to extract certificates from PKCS#12 file."
        echo "This could be due to password protection or file corruption."
        return 1
    fi

    # Process the extracted certificates
    local all_certs_text
    all_certs_text=$(openssl crl2pkcs7 -nocrl -certfile "$tempPem" 2>/dev/null | \
                    openssl pkcs7 -print_certs -text -noout 2>/dev/null)

    if [ $? -eq 0 ] && [ -n "$all_certs_text" ]; then
        parse_certs_info "$all_certs_text"
        if (( cert_count > 1 )); then
            echo "Complete Chain Verification:"
            verify_chain "$tempPem" "$ca_file"
        fi
    else
        # Try alternative method if the first one fails
        all_certs_text=$(openssl x509 -in "$tempPem" -text -noout 2>/dev/null)
        if [ $? -eq 0 ] && [ -n "$all_certs_text" ]; then
            parse_cert_info "$all_certs_text"
        else
            echo "Error: Failed to process extracted certificates"
            return 1
        fi
    fi
}

# Function to detect if file is PKCS#12
is_pkcs12() {
    local file="$1"
    # Try multiple detection methods
    if file "$file" | grep -qi "PKCS.*12"; then
        return 0  # File command identifies it as PKCS#12
    elif openssl pkcs12 -info -in "$file" -nokeys -nomacver -password pass: 2>&1 | grep -q "PKCS7"; then
        return 0  # OpenSSL identifies it as PKCS#12
    elif [[ "$file" =~ \.(pfx|p12)$ ]]; then
        return 0  # File extension suggests PKCS#12
    fi
    return 1  # Not a PKCS#12 file or can't be read
}

# Function to process PEM files
process_pem() {
    local file="$1"
    local cert_text
    local all_certs_text

    if [ "$file" = "" ]; then
        # Reading from stdin
        all_certs_text=$(cat - | openssl crl2pkcs7 -nocrl -certfile /dev/stdin 2>/dev/null | \
                        openssl pkcs7 -print_certs -text -noout 2>/dev/null)
    else
        all_certs_text=$(openssl crl2pkcs7 -nocrl -certfile "$file" 2>/dev/null | \
                        openssl pkcs7 -print_certs -text -noout 2>/dev/null)
    fi

    if [ $? -eq 0 ] && [ -n "$all_certs_text" ]; then
        parse_certs_info "$all_certs_text"
        if (( cert_count > 1 )); then
            echo "Complete Chain Verification:"
            if [ "$file" = "" ]; then
                # For stdin, we need to create a temporary file
                local tempPem="/tmp/certcheck_temp_$$.pem"
                trap 'rm -f "$tempPem"' EXIT
                cat - > "$tempPem"
                verify_chain "$tempPem" "$ca_file"
            else
                verify_chain "$file" "$ca_file"
            fi
        fi
        return 0
    fi

    # Try as single certificate if bundle processing failed
    if [ "$file" = "" ]; then
        cert_text=$(cat - | openssl x509 -text -noout 2>/dev/null)
    else
        cert_text=$(openssl x509 -in "$file" -text -noout 2>/dev/null)
    fi

    if [ $? -eq 0 ]; then
        parse_cert_info "$cert_text"
        return 0
    fi

    echo "Error: File is neither a valid certificate nor a certificate bundle"
    return 1
}

# Main processing function
process_file() {
    local file="$1"
    local from_stdin="$2"

    if [ "$from_stdin" = "true" ]; then
        process_pem ""
        return
    fi

    echo "=== Checking file: $file ==="

    # First try to detect if it's a PKCS#12 file
    if is_pkcs12 "$file"; then
        echo "Detected PKCS#12 format..."
        process_pkcs12 "$file"
    else
        # Try processing as PEM/regular certificate
        process_pem "$file"
    fi
}

# Function to get certificate chain from keychain
get_chain_from_keychain() {
    local name="$1"
    local tempPem="/tmp/certcheck_temp_$$.pem"
    trap 'rm -f "$tempPem"' EXIT

    echo "Fetching certificate chain from keychain..."

    # Get the end-entity certificate
    echo "Getting certificate for CN=$name"
    if ! security find-certificate -c "$name" -p > "$tempPem" 2>/dev/null; then
        echo "Error: Could not find certificate with CN=$name in keychain"
        return 1
    fi

    # Get the issuer's CN
    local issuer
    echo "Getting issuer for $name"
    issuer=$(openssl x509 -in "$tempPem" -noout -issuer 2>/dev/null | sed -n 's/.*CN=\([^,]*\).*/\1/p')
    echo "Found issuer: $issuer"

    while [ -n "$issuer" ]; do
        echo "Getting certificate for issuer CN=$issuer"
        # Append the issuer's certificate
        if ! security find-certificate -c "$issuer" -p >> "$tempPem" 2>/dev/null; then
            echo "Warning: Could not find issuer certificate with CN=$issuer in keychain"
            break
        fi

        # Get the next issuer before checking if we're at the root
        local next_issuer
        next_issuer=$(security find-certificate -c "$issuer" -p 2>/dev/null | \
                     openssl x509 -noout -issuer 2>/dev/null | \
                     sed -n 's/.*CN=\([^,]*\).*/\1/p')

        # Check if this is a root (self-signed) certificate
        local subject
        subject=$(security find-certificate -c "$issuer" -p 2>/dev/null | \
                 openssl x509 -noout -subject 2>/dev/null | \
                 sed -n 's/.*CN=\([^,]*\).*/\1/p')

        if [ "$subject" = "$issuer" ] && [ "$next_issuer" = "$issuer" ]; then
            echo "Found root certificate (self-signed): $subject"
            break
        fi

        if [ -z "$next_issuer" ]; then
            echo "No further issuer found after: $issuer"
            break
        fi

        issuer="$next_issuer"
        echo "Next issuer: $issuer"
    done

    echo "Processing complete certificate chain..."
    process_pem "$tempPem"
}

###############################################################################
# main
###############################################################################
main() {
    # Add -s or --stdin option
    local from_stdin=false
    local chain_name=""

    # Parse command-line options
    local ca_file=""
    local dir=""
    local pattern=""
    local files=()

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                usage
                ;;
            -c|--ca-file)
                if [[ -n "$2" && ! "$2" =~ ^- ]]; then
                    ca_file="$2"
                    shift 2
                else
                    echo "Error: --ca-file requires a non-empty option argument."
                    exit 1
                fi
                ;;
            -d|--dir)
                if [[ -n "$2" && ! "$2" =~ ^- ]]; then
                    dir="$2"
                    shift 2
                else
                    echo "Error: --dir requires a non-empty option argument."
                    exit 1
                fi
                ;;
            -p|--pattern)
                if [[ -n "$2" && ! "$2" =~ ^- ]]; then
                    pattern="$2"
                    shift 2
                else
                    echo "Error: --pattern requires a non-empty option argument."
                    exit 1
                fi
                ;;
            -s|--stdin)
                from_stdin=true
                shift
                ;;
            -n|--chain)
                if [[ -n "$2" && ! "$2" =~ ^- ]]; then
                    chain_name="$2"
                    shift 2
                else
                    echo "Error: --chain requires a certificate common name."
                    exit 1
                fi
                ;;
            *)
                files+=("$1")
                shift
                ;;
        esac
    done

    if [ -n "$chain_name" ]; then
        get_chain_from_keychain "$chain_name"
    elif [ "$from_stdin" = true ]; then
        process_file "" "true"
    elif [ -n "$dir" ]; then
        if [ ! -d "$dir" ]; then
            echo "Error: Directory '$dir' not found."
            exit 1
        fi
        cd "$dir" || exit 1
        # Find all certificate files in directory
        while IFS= read -r -d '' file; do
            process_file "$file" "false"
        done < <(find . -maxdepth 1 -type f \( -name "*.pem" -o -name "*.p12" -o -name "*.pfx" -o -name "*.crt" \) -print0)
    # Handle pattern matching
    elif [ -n "$pattern" ]; then
        IFS=',' read -ra patterns <<< "$pattern"
        for pat in "${patterns[@]}"; do
            # Remove any whitespace
            pat="${pat// /}"
            # Check if any files match the pattern
            for file in $pat; do
                [ -f "$file" ] && process_file "$file" "false"
            done
        done
    # Handle explicit file list
    elif [ ${#files[@]} -gt 0 ]; then
        for file in "${files[@]}"; do
            process_file "$file" "false"
        done
    else
        echo "Error: No input files specified."
        usage
    fi

    echo "Done."
    exit $GLOBAL_EXIT_CODE
}

main "$@"
