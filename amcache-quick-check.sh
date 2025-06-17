#!/bin/bash

# Color definitions
RED='\033[1;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Default scope and json output
SCOPE="system"
JSON_OUTPUT="no"
# Set your VirusTotal API key
API_KEY=""

# Check if API key is set
if [[ -z "$API_KEY" || "$API_KEY" == "YOUR_API_KEY_HERE" ]]; then
    echo ""
    echo -e "${YELLOW}[!] No VirusTotal API key set. VirusTotal checks will not be performed.${NC}"
    echo ""
    API_KEY=""
fi


# Parse options
while [[ $# -gt 0 ]]; do
    case "$1" in
        --scope)
            shift
            if [[ "$1" == "users" || "$1" == "system" ]]; then
                SCOPE="$1"
            else
                echo -e "${RED}Invalid scope: $1. Use 'users' or 'system'.${NC}"
                exit 1
            fi
            shift
            ;;
        --json-output)
            shift
            if [[ "$1" == "yes" || "$1" == "no" ]]; then
                JSON_OUTPUT="$1"
            else
                echo -e "${RED}Invalid json-output: $1. Use 'yes' or 'no'.${NC}"
                exit 1
            fi
            shift
            ;;
        -*)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
        *)
            AMCACHE_FILE="$1"
            shift
            ;;
    esac
done

# Usage check
if [ -z "$AMCACHE_FILE" ]; then
    echo -e "${RED}Usage: $0 [--scope users|system] [--json-output yes|no] <amcache_file.txt>${NC}"
    exit 1
fi


# Check if file exists
if [ ! -f "$AMCACHE_FILE" ]; then
    echo -e "${RED}File not found: $AMCACHE_FILE${NC}"
    exit 2
fi

if [[ "$SCOPE" == "users" ]]; then
    # Cerca solo file nelle cartelle "users"
    grep -i '\.exe' "$AMCACHE_FILE" | awk -F'\t' '
    NR==1 {next}
    tolower($3) ~ /microsoft/ {next}
    gsub(/^[ \t]+|[ \t]+$/, "", $3)
    $3 != "-"        {next}
    $8 !~ /^[0-9a-fA-F]{40}$/ {next}
    tolower($2) !~ /\\users\\/ {next}
    {
        gsub(/\\/,"\\\\",$2)
        gsub(/"/,"\\\"",$2)
        if(rec++) print ",";
        printf "  {\"path\":\"%s\",\"sha1\":\"%s\",\"lastModify\":\"%s\"}", $2, $8, $4
    }
    END { print rec? "\n]" : "[]" }
    BEGIN { print "[" }
    ' > amcache_hashes.json
else
    # Cerca in tutto il sistema
    grep -i '\.exe' "$AMCACHE_FILE" | awk -F'\t' '
    NR==1 {next}
    tolower($3) ~ /microsoft/ {next}
    gsub(/^[ \t]+|[ \t]+$/, "", $3)
    $3 != "-"        {next}
    $8 !~ /^[0-9a-fA-F]{40}$/ {next}
    {
        gsub(/\\/,"\\\\",$2)
        gsub(/"/,"\\\"",$2)
        if(rec++) print ",";
        printf "  {\"path\":\"%s\",\"sha1\":\"%s\",\"lastModify\":\"%s\"}", $2, $8, $4
    }
    END { print rec? "\n]" : "[]" }
    BEGIN { print "[" }
    ' > amcache_hashes.json
fi

if [[ -n "$API_KEY" ]]; then
    jq -r '.[] | [.path, .sha1, .lastModify] | @tsv' amcache_hashes.json |
    while IFS=$'\t' read -r path sha1 lastModify; do
        echo -e "${YELLOW}[!] Warning: The file may be suspicious due to an ambiguous VERSIONINFO block.${NC}"
        echo ""
        echo -e "${CYAN}[*] Querying file:${NC} $path"
        echo -e "${CYAN}[*] Querying SHA1:${NC} $sha1"
        echo -e "${CYAN}[*] Last Time:${NC} $lastModify"
        result=$(curl --silent --request GET \
             --url "https://www.virustotal.com/api/v3/files/$sha1" \
             --header "x-apikey: $API_KEY" \
        | jq '.data.attributes.last_analysis_stats')

        if [[ $result == "null" ]]; then
            echo ""
            echo -e "${YELLOW}[!] No results found on VirusTotal.${NC}"
        else
            malicious=$(echo "$result" | jq '.malicious')
            suspicious=$(echo "$result" | jq '.suspicious')
            harmless=$(echo "$result" | jq '.harmless')
            undetected=$(echo "$result" | jq '.undetected')

            echo -e "${GREEN}Harmless:${NC}   $harmless"
            echo -e "${YELLOW}Suspicious:${NC} $suspicious"
            echo -e "${RED}Malicious:${NC}  $malicious"
            echo -e "${CYAN}Undetected:${NC} $undetected"
        fi     
        echo ""   
        echo -e "${CYAN}------------------------------------------------------------------------------${NC}"
        echo ""
    done
else
    jq -r '.[] | [.path, .sha1, .lastModify] | @tsv' amcache_hashes.json |
    # jq -r '.[] | .path' amcache_hashes.json |
    while IFS=$'\t' read -r path sha1 lastModify; do
        echo -e "${YELLOW}[!] Warning: The file may be suspicious due to an ambiguous VERSIONINFO block.${NC}"
        echo -e "${CYAN}[*] File:${NC} $path"
        echo -e "${CYAN}[*] Sha1:${NC} $sha1"
        echo -e "${CYAN}[*] Last Time:${NC} $lastModify"
        echo ""
        echo -e "${CYAN}------------------------------------------------------------------------------${NC}"
        echo ""
    done
    echo -e "${YELLOW}[!] No VirusTotal API key set. VirusTotal checks will not be performed.${NC}"
    echo ""
fi

# Remove JSON file if not requested
if [[ "$JSON_OUTPUT" == "no" ]]; then
    rm -f amcache_hashes.json
fi
