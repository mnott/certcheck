# Certificate Checker

A robust Bash script for checking and validating X.509 certificates in PEM and PKCS#12 formats. This tool helps you monitor certificate expiration dates and verify certificate chains.

## Features

- Supports multiple certificate formats:
  - PEM format (with "-----BEGIN CERTIFICATE-----")
  - PKCS#12 format (.p12/.pfx files)
- Provides detailed certificate information:
  - Subject
  - Issuer
  - Validity dates
  - Certificate type (Root or Intermediate)
  - Days remaining until expiration
- Validates certificate chains
- Color-coded output for easy status identification
- Flexible input options:
  - Check single certificate file
  - Scan entire directories
  - Process files matching specific patterns
  - Read certificates from stdin
  - Fetch and verify certificate chains from macOS keychain

## Prerequisites

### For macOS
- Bash shell (comes pre-installed)
- OpenSSL
  - Install via Homebrew: `brew install openssl`
  - Or via MacPorts: `sudo port install openssl`
- Perl (comes pre-installed)
- GNU sed
  - Install via Homebrew: `brew install gnu-sed`
  - Or via MacPorts: `sudo port install gsed`

### For Linux (Debian/Ubuntu)
- Bash shell (comes pre-installed)
- OpenSSL: `sudo apt-get install openssl`
- Perl (comes pre-installed)

### For Linux (RHEL/CentOS/Fedora)
- Bash shell (comes pre-installed)
- OpenSSL: `sudo dnf install openssl`
- Perl (comes pre-installed)

## Installation

1. Download the script:

curl -O https://github.com/mnott/certcheck/blob/main/certcheck.sh

2. Make it executable:

chmod +x certcheck.sh

## Usage

./certcheck.sh [options] <certificate-file(s)>

### Options

- `-h, --help`: Display help message and exit
- `-c, --ca-file <file>`: Specify a custom Root CA file for chain verification
- `-d, --dir <dir>`: Check all certificate files in specified directory
- `-p, --pattern <pat>`: Check files matching pattern (e.g., '*.pem,*.p12')
- `-s, --stdin`: Read certificate from standard input
- `-n, --chain <name>`: Check certificate chain from macOS keychain by common name

### Examples

Check a single certificate:

./certcheck.sh cert.pem

Check all certificates in a directory:

./certcheck.sh -d /path/to/certs

Check current directory:

./certcheck.sh -d .

Check files matching specific patterns:

./certcheck.sh -p '*.pem,*.p12'

Verify with a custom CA file:

./certcheck.sh -c /path/to/rootCA.pem cert.p12

Read certificate from stdin:

cat cert.pem | ./certcheck.sh -s

Check certificate chain from macOS keychain:

./certcheck.sh -n "I052341"

## Exit Codes

- `0`: All certificates are valid and not near expiry
- `1`: Error in script execution
- `2`: At least one certificate is expired or near expiry (< 30 days)

## Output Information

For each certificate, the script displays:
- Subject name
- Issuer name
- Valid from date
- Expiration date
- Certificate type (Root or Intermediate)
- Expiry status with color coding:
  - 🟢 Green: Valid for > 90 days
  - 🟡 Yellow: Warning for < 90 days
  - 🔴 Red: Critical for < 30 days or expired

## Chain Verification

When multiple certificates are present in a file, the script automatically performs chain verification:
1. First attempts verification using certificates in the file
2. If a custom CA file is provided, tries verification with it
3. Finally attempts verification using the system's CA store

## macOS Keychain Integration

The script can fetch and verify complete certificate chains from the macOS keychain using the `-n` or `--chain` option. This feature:

- Retrieves the specified certificate by Common Name (CN)
- Automatically follows the chain of trust by fetching each issuer certificate
- Stops when it reaches a root (self-signed) certificate
- Displays and verifies the complete chain


## License

This script is released under the [WTFPL License](https://en.wikipedia.org/wiki/WTFPL).

## Contributing

Feel free to submit issues and pull requests.



