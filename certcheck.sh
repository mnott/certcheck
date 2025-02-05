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
    echo
    echo "Examples:"
    echo "  $0 cert.pem                         # Check single file"
    echo "  $0 -d /path/to/certs                # Check all certs in directory, pass . as argument for current directory"
    echo "  $0 -p '*.pem,*.p12'                 # Check files matching patterns"
    echo "  $0 -c /path/to/rootCA.pem cert.p12  # Check with custom CA"
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

# Process a single certificate file
process_file() {
    local file="$1"
    local ca_file="$2"

    if [ ! -f "$file" ]; then
        echo "Error: File '$file' not found."
        return 1
    fi

    echo "=== Checking file: $file ==="

    # Reset cert_count for each file
    cert_count=0

    if grep -Fq -- "-----BEGIN CERTIFICATE-----" "$file"; then
        # ---------------------------------------------------------------------
        # It's PEM
        # ---------------------------------------------------------------------
        debug "File appears to be PEM (contains 'BEGIN CERTIFICATE')."

        # Convert (PEM -> PKCS7) -> text and capture the output
        local all_certs_text
        all_certs_text=$(
            openssl crl2pkcs7 -nocrl -certfile "$file" 2>/dev/null \
            | openssl pkcs7 -print_certs -text -noout 2>/dev/null \
            | sed '/-----BEGIN CERTIFICATE-----/d' \
              | sed '/-----END CERTIFICATE-----/d'
        )

        # Check if conversion was successful
        if [ -z "$all_certs_text" ]; then
            echo "Error: Failed to process PEM file."
            exit 1
        fi

        # Parse each certificate
        parse_certs_info "$all_certs_text"

        # Verify chain only if multiple certificates are present
        if (( cert_count > 1 )); then
            echo "Complete Chain Verification:"
            verify_chain "$file" "$ca_file"
        else
            echo "Note: Only one certificate found. Skipping full chain verification."
        fi

    else
        # ---------------------------------------------------------------------
        # It's PKCS#12 (because there's no "-----BEGIN CERTIFICATE-----")
        # ---------------------------------------------------------------------
        debug "File is likely PKCS#12 (no BEGIN CERTIFICATE found)."

        # Extract all public certs into unencrypted PEM (prompts once if needed)
        local tempPem="/tmp/certcheck_temp_$$.pem"
        # Use trap to ensure tempPem is deleted on exit
        trap 'rm -f "$tempPem"' EXIT

        if ! openssl pkcs12 \
            -in "$file" \
            -nokeys -clcerts -nodes \
            -out "$tempPem" >/dev/null 2>&1
        then
            echo "Failed to decode file as PKCS#12."
            exit 1
        fi

        # Convert that unencrypted PEM to text and capture the output
        local all_certs_text
        all_certs_text=$(
            openssl crl2pkcs7 -nocrl -certfile "$tempPem" 2>/dev/null \
            | openssl pkcs7 -print_certs -text -noout 2>/dev/null \
            | sed '/-----BEGIN CERTIFICATE-----/d' \
              | sed '/-----END CERTIFICATE-----/d'
        )

        # Check if conversion was successful
        if [ -z "$all_certs_text" ]; then
            echo "Error: Failed to process extracted PEM from PKCS#12."
            exit 1
        fi

        # Parse each certificate
        parse_certs_info "$all_certs_text"

        # Verify chain only if multiple certificates are present
        if (( cert_count > 1 )); then
            echo "Complete Chain Verification:"
            verify_chain "$tempPem" "$ca_file"
        else
            echo "Note: Only one certificate found. Skipping full chain verification."
        fi

        # Cleanup is handled by trap
    fi

    echo
}

###############################################################################
# main
###############################################################################
main() {
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
            *)
                files+=("$1")
                shift
                ;;
        esac
    done

    # Handle directory scanning
    if [ -n "$dir" ]; then
        if [ ! -d "$dir" ]; then
            echo "Error: Directory '$dir' not found."
            exit 1
        fi
        cd "$dir" || exit 1
        # Find all certificate files in directory
        while IFS= read -r -d '' file; do
            process_file "$file" "$ca_file"
        done < <(find . -maxdepth 1 -type f \( -name "*.pem" -o -name "*.p12" -o -name "*.pfx" -o -name "*.crt" \) -print0)
    # Handle pattern matching
    elif [ -n "$pattern" ]; then
        IFS=',' read -ra patterns <<< "$pattern"
        for pat in "${patterns[@]}"; do
            # Remove any whitespace
            pat="${pat// /}"
            # Check if any files match the pattern
            for file in $pat; do
                [ -f "$file" ] && process_file "$file" "$ca_file"
            done
        done
    # Handle explicit file list
    elif [ ${#files[@]} -gt 0 ]; then
        for file in "${files[@]}"; do
            process_file "$file" "$ca_file"
        done
    else
        echo "Error: No input files specified."
        usage
    fi

    echo "Done."
    exit $GLOBAL_EXIT_CODE
}

main "$@"
